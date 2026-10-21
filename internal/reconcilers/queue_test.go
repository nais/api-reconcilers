package reconcilers_test

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
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
		q := reconcilers.NewQueue()
		defer q.Close()
		if err := q.Add(input); err != nil {
			t.Fatal(err)
		}
		got, shutdown := q.Get()
		if shutdown || got != input {
			t.Fatalf("expected input, got %v (shutdown: %v)", got, shutdown)
		}
		q.Done(got)
	})

	t.Run("concurrent add and close", func(t *testing.T) {
		q := reconcilers.NewQueue()
		var wg sync.WaitGroup
		wg.Go(func() {
			for range 100 {
				_ = q.Add(input)
				_, _ = q.Retry(input)
			}
		})
		q.Close()
		wg.Wait()
	})

	t.Run("close queue", func(t *testing.T) {
		q := reconcilers.NewQueue()
		q.Close()
		q.Close()
		if err := q.Add(input); err == nil {
			t.Fatal("expected error when adding to closed queue")
		}
		if _, err := q.Retry(input); err == nil {
			t.Fatal("expected error when retrying on closed queue")
		}
		if _, shutdown := q.Get(); !shutdown {
			t.Fatal("expected closed queue")
		}
	})

	t.Run("adding does not block when many teams are queued", func(t *testing.T) {
		q := reconcilers.NewQueue()
		defer q.Close()
		for i := range 5000 {
			if err := q.Add(reconcilers.ReconcileRequest{TeamSlug: fmt.Sprint(i)}); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("team events share one queue entry and use latest metadata", func(t *testing.T) {
		q := reconcilers.NewQueue()
		defer q.Close()
		updated := input
		updated.CorrelationID = uuid.New().String()
		updated.TraceID = "latest-trace"
		for _, req := range []reconcilers.ReconcileRequest{input, updated} {
			if err := q.Add(req); err != nil {
				t.Fatal(err)
			}
		}
		got, _ := q.Get()
		if got != updated {
			t.Fatalf("expected latest request metadata, got %v", got)
		}
		q.Done(got)
		q.Close()
		if _, shutdown := q.Get(); !shutdown {
			t.Fatal("expected one queue entry for both events")
		}
	})

	t.Run("duplicate requests are not processed concurrently", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			q := reconcilers.NewQueue()
			defer q.Close()
			if err := q.Add(input); err != nil {
				t.Fatal(err)
			}
			first, _ := q.Get()
			updated := input
			updated.CorrelationID = uuid.New().String()
			if err := q.Add(updated); err != nil {
				t.Fatal(err)
			}
			if err := q.Add(input); err != nil {
				t.Fatal(err)
			}
			received := make(chan reconcilers.ReconcileRequest, 1)
			go func() {
				next, _ := q.Get()
				received <- next
			}()
			synctest.Wait()
			select {
			case <-received:
				t.Fatal("request was processed before the first attempt finished")
			default:
			}
			q.Done(first)
			if next := <-received; next != input {
				t.Fatalf("unexpected request: %v", next)
			}
			q.Done(input)
		})
	})

	t.Run("delayed retry allows other teams to proceed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			q := reconcilers.NewQueue()
			defer q.Close()
			start := time.Now()
			delay, err := q.Retry(input)
			if err != nil || delay != 10*time.Second {
				t.Fatalf("unexpected retry delay %v, error %v", delay, err)
			}
			other := reconcilers.ReconcileRequest{TeamSlug: "other-team"}
			if err := q.Add(other); err != nil {
				t.Fatal(err)
			}
			got, _ := q.Get()
			if got != other || time.Since(start) != 0 {
				t.Fatalf("expected other team immediately, got %v after %v", got, time.Since(start))
			}
			q.Done(got)
			got, _ = q.Get()
			if got != input || time.Since(start) != delay {
				t.Fatalf("expected retry after %v, got %v after %v", delay, got, time.Since(start))
			}
			q.Done(got)
		})
	})

	t.Run("retry backoff is capped and resets on success", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			q := reconcilers.NewQueue()
			defer q.Close()
			for _, want := range []time.Duration{10, 20, 40, 80, 160, 300, 300} {
				delay, err := q.Retry(input)
				if err != nil || delay != want*time.Second {
					t.Fatalf("expected delay %v, got %v, error %v", want*time.Second, delay, err)
				}
				start := time.Now()
				got, shutdown := q.Get()
				if shutdown || got != input || time.Since(start) != delay {
					t.Fatalf("unexpected retry %v after %v (shutdown: %v)", got, time.Since(start), shutdown)
				}
				q.Done(got)
			}
			q.Forget(input)
			delay, err := q.Retry(input)
			if err != nil || delay != 10*time.Second {
				t.Fatalf("expected reset backoff, got %v, error %v", delay, err)
			}
		})
	})

	t.Run("backoff is shared across events for the same team", func(t *testing.T) {
		q := reconcilers.NewQueue()
		defer q.Close()
		if _, err := q.Retry(input); err != nil {
			t.Fatal(err)
		}
		updated := input
		updated.CorrelationID = uuid.New().String()
		delay, err := q.Retry(updated)
		if err != nil || delay != 20*time.Second {
			t.Fatalf("expected shared team backoff, got %v, error %v", delay, err)
		}
		q.Forget(updated)
		delay, err = q.Retry(input)
		if err != nil || delay != 10*time.Second {
			t.Fatalf("expected shared backoff reset, got %v, error %v", delay, err)
		}
	})

	t.Run("shutdown cancels pending retries and unblocks workers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			q := reconcilers.NewQueue()
			if _, err := q.Retry(input); err != nil {
				t.Fatal(err)
			}
			stopped := make(chan bool, 1)
			go func() {
				_, shutdown := q.Get()
				stopped <- shutdown
			}()
			synctest.Wait()
			q.Close()
			if !<-stopped {
				t.Fatal("expected worker to stop without processing delayed retry")
			}
		})
	})
}
