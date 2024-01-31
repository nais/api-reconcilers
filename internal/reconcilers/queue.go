package reconcilers

import (
	"fmt"
	"sync"

	"github.com/nais/api/pkg/protoapi"
)

const reconcilerQueueSize = 4096

type input struct {
	correlationID string
	traceID       string
	team          *protoapi.Team
}

type Queue interface {
	Add(input) error
	Close()
}

type queue struct {
	queue  chan input
	closed bool
	lock   sync.Mutex
}

func NewQueue() (Queue, <-chan input) {
	ch := make(chan input, reconcilerQueueSize)
	return &queue{
		queue:  ch,
		closed: false,
	}, ch
}

func (q *queue) Add(input input) error {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.closed {
		return fmt.Errorf("team reconciler channel is closed")
	}

	q.queue <- input
	return nil
}

func (q *queue) Close() {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.closed = true
	close(q.queue)
}
