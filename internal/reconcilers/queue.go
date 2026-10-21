package reconcilers

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"
)

const (
	reconcilerRetryDelay    = 10 * time.Second
	reconcilerMaxRetryDelay = 5 * time.Minute
)

type ReconcileRequest struct {
	CorrelationID string
	TraceID       string
	TeamSlug      string
}

type Queue interface {
	Add(ReconcileRequest) error
	Get() (ReconcileRequest, bool)
	Done(ReconcileRequest)
	Retry(ReconcileRequest) (time.Duration, error)
	Forget(ReconcileRequest)
	Close()
}

// Team keys ensure one retry chain and at most one active worker per team.
type queue struct {
	queue       workqueue.TypedInterface[string]
	rateLimiter workqueue.TypedRateLimiter[string]
	lock        sync.Mutex
	requests    map[string]*pendingRequest
}

type pendingRequest struct {
	request ReconcileRequest
	retry   bool
	timer   *time.Timer
}

func NewQueue() Queue {
	rateLimiter := workqueue.NewTypedItemExponentialFailureRateLimiter[string](reconcilerRetryDelay, reconcilerMaxRetryDelay)
	return &queue{
		queue:       workqueue.NewTyped[string](),
		rateLimiter: rateLimiter,
		requests:    make(map[string]*pendingRequest),
	}
}

func (q *queue) Add(req ReconcileRequest) error {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.queue.ShuttingDown() {
		return fmt.Errorf("team reconciler channel is closed")
	}

	q.removePending(req.TeamSlug)
	q.requests[req.TeamSlug] = &pendingRequest{request: req}
	q.queue.Add(req.TeamSlug)
	return nil
}

func (q *queue) Get() (ReconcileRequest, bool) {
	for {
		slug, shutdown := q.queue.Get()
		if shutdown {
			return ReconcileRequest{}, true
		}
		q.lock.Lock()
		pending := q.requests[slug]
		// Canceled retries can leave a key ready or already claimed by a worker.
		if pending == nil || pending.timer != nil {
			q.queue.Done(slug)
			q.lock.Unlock()
			continue
		}
		delete(q.requests, slug)
		if !pending.retry {
			// Reset when the fresh attempt starts, after any older attempt has finished.
			q.rateLimiter.Forget(slug)
		}
		req := pending.request
		q.lock.Unlock()
		return req, false
	}
}

func (q *queue) Done(req ReconcileRequest) {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.queue.Done(req.TeamSlug)
	if q.requests[req.TeamSlug] == nil {
		q.rateLimiter.Forget(req.TeamSlug)
	}
}

func (q *queue) Retry(req ReconcileRequest) (time.Duration, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.queue.ShuttingDown() {
		return 0, fmt.Errorf("team reconciler channel is closed")
	}

	delay := q.rateLimiter.When(req.TeamSlug)
	// A newer event already guarantees another attempt; it must not be replaced by a retry.
	if pending := q.requests[req.TeamSlug]; pending != nil && !pending.retry {
		return delay, nil
	}
	q.removePending(req.TeamSlug)
	pending := &pendingRequest{request: req, retry: true}
	q.requests[req.TeamSlug] = pending
	pending.timer = time.AfterFunc(delay, func() {
		q.lock.Lock()
		defer q.lock.Unlock()
		// Stop may race with a callback that has already started.
		if q.requests[req.TeamSlug] != pending {
			return
		}
		pending.timer = nil
		q.queue.Add(req.TeamSlug)
	})
	return delay, nil
}

func (q *queue) Forget(req ReconcileRequest) {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.rateLimiter.Forget(req.TeamSlug)
	if pending := q.requests[req.TeamSlug]; pending != nil && pending.retry {
		q.removePending(req.TeamSlug)
	}
}

func (q *queue) Close() {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.queue.ShutDown()
	for slug := range q.requests {
		q.removePending(slug)
		q.rateLimiter.Forget(slug)
	}
}

func (q *queue) removePending(slug string) {
	if pending := q.requests[slug]; pending != nil {
		if pending.timer != nil {
			pending.timer.Stop()
		}
		delete(q.requests, slug)
	}
}
