package reconcilers

import (
	"fmt"
	"sync"
)

const reconcilerQueueSize = 4096

type ReconcileRequest struct {
	CorrelationID string
	TraceID       string
	TeamSlug      string
	Delete        bool
}

type Queue interface {
	Add(ReconcileRequest) error
	Close()
}

type queue struct {
	queue  chan ReconcileRequest
	closed bool
	lock   sync.Mutex
}

func NewQueue() (Queue, <-chan ReconcileRequest) {
	ch := make(chan ReconcileRequest, reconcilerQueueSize)
	return &queue{
		queue:  ch,
		closed: false,
	}, ch
}

func (q *queue) Add(req ReconcileRequest) error {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.closed {
		return fmt.Errorf("team reconciler channel is closed")
	}

	q.queue <- req
	return nil
}

func (q *queue) Close() {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.closed = true
	close(q.queue)
}
