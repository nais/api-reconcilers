package reconcilers

import (
	"fmt"
	"sync"

	"github.com/nais/api/pkg/protoapi"
)

const reconcilerQueueSize = 4096

type Input struct {
	CorrelationID string
	TraceID       string
	Team          *protoapi.Team
}

type Queue interface {
	Add(Input) error
	Close()
}

type queue struct {
	queue  chan Input
	closed bool
	lock   sync.Mutex
}

func NewQueue() (Queue, <-chan Input) {
	ch := make(chan Input, reconcilerQueueSize)
	return &queue{
		queue:  ch,
		closed: false,
	}, ch
}

func (q *queue) Add(input Input) error {
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
