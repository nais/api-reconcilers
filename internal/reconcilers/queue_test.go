package reconcilers_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nais/api-reconcilers/internal/reconcilers"
)

func Test_Queue(t *testing.T) {
	input := reconcilers.ReconcileRequest{
		TeamSlug:      "test-team",
		CorrelationID: uuid.New().String(),
	}

	t.Run("add to queue", func(t *testing.T) {
		q, ch := reconcilers.NewQueue()
		if q.Add(input) != nil {
			t.Errorf("expected no error when adding to queue")
		}

		if len(ch) != 1 {
			t.Errorf("expected queue to contain one item")
		}

		if input != <-ch {
			t.Errorf("expected input to match")
		}

		if len(ch) != 0 {
			t.Errorf("expected queue to be empty")
		}
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

		if q.Add(input).Error() != "team reconciler channel is closed" {
			t.Errorf("expected error when adding to closed queue")
		}
	})
}
