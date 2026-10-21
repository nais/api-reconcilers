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
	queue       workqueue.TypedDelayingInterface[string]
	rateLimiter workqueue.TypedRateLimiter[string]
	lock        sync.Mutex
	requests    map[string]ReconcileRequest
}

func NewQueue() Queue {
	rateLimiter := workqueue.NewTypedItemExponentialFailureRateLimiter[string](reconcilerRetryDelay, reconcilerMaxRetryDelay)
	return &queue{
		queue:       workqueue.NewTypedDelayingQueue[string](),
		rateLimiter: rateLimiter,
		requests:    make(map[string]ReconcileRequest),
	}
}

func (q *queue) Add(req ReconcileRequest) error {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.queue.ShuttingDown() {
		return fmt.Errorf("team reconciler channel is closed")
	}

	q.requests[req.TeamSlug] = req
	q.queue.Add(req.TeamSlug)
	return nil
}

func (q *queue) Get() (ReconcileRequest, bool) {
	slug, shutdown := q.queue.Get()
	if shutdown {
		return ReconcileRequest{}, true
	}
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.requests[slug], false
}

func (q *queue) Done(req ReconcileRequest) {
	q.queue.Done(req.TeamSlug)
}

func (q *queue) Retry(req ReconcileRequest) (time.Duration, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.queue.ShuttingDown() {
		return 0, fmt.Errorf("team reconciler channel is closed")
	}

	if _, exists := q.requests[req.TeamSlug]; !exists {
		q.requests[req.TeamSlug] = req
	}
	delay := q.rateLimiter.When(req.TeamSlug)
	q.queue.AddAfter(req.TeamSlug, delay)
	return delay, nil
}

func (q *queue) Forget(req ReconcileRequest) {
	q.rateLimiter.Forget(req.TeamSlug)
}

func (q *queue) Close() {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.queue.ShutDown()
}
