package reconcilers_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/reconcilers"
	"github.com/nais/api/pkg/protoapi"
	"github.com/stretchr/testify/assert"
)

func Test_Queue(t *testing.T) {
	input := reconcilers.Input{
		Team:          &protoapi.Team{Slug: "test-team"},
		CorrelationID: uuid.New().String(),
	}

	t.Run("add to queue", func(t *testing.T) {
		q, ch := reconcilers.NewQueue()
		assert.Nil(t, q.Add(input))
		assert.Len(t, ch, 1)
		assert.Equal(t, input, <-ch)
		assert.Len(t, ch, 0)
	})

	t.Run("race test", func(t *testing.T) {
		q, _ := reconcilers.NewQueue()
		go func(q reconcilers.Queue) {
			for i := 0; i < 100; i++ {
				_ = q.Add(input)
				time.Sleep(time.Millisecond)
			}
		}(q)
		q.Close()
	})

	t.Run("close channel", func(t *testing.T) {
		q, _ := reconcilers.NewQueue()
		q.Close()
		assert.EqualError(t, q.Add(input), "team reconciler channel is closed")
	})
}
