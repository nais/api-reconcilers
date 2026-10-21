package reconcilers

import (
	"testing"
	"testing/synctest"
	"time"
)

type queueGetResult struct {
	request  ReconcileRequest
	shutdown bool
}

func queueGetAsync(q Queue) <-chan queueGetResult {
	result := make(chan queueGetResult, 1)
	go func() {
		req, shutdown := q.Get()
		result <- queueGetResult{request: req, shutdown: shutdown}
	}()
	return result
}

func queueExpectRequest(t *testing.T, result <-chan queueGetResult, want ReconcileRequest) {
	t.Helper()
	synctest.Wait()
	select {
	case got := <-result:
		if got.shutdown || got.request != want {
			t.Fatalf("Get() = %+v, want request %+v", got, want)
		}
	default:
		t.Fatalf("Get() did not return request %+v", want)
	}
}

func queueExpectBlocked(t *testing.T, result <-chan queueGetResult) {
	t.Helper()
	synctest.Wait()
	select {
	case got := <-result:
		t.Fatalf("unexpected Get() result: %+v", got)
	default:
	}
}

func queueAdd(t *testing.T, q Queue, req ReconcileRequest) {
	t.Helper()
	if err := q.Add(req); err != nil {
		t.Fatal(err)
	}
}

func queueRetry(t *testing.T, q Queue, req ReconcileRequest, want time.Duration) {
	t.Helper()
	if delay, err := q.Retry(req); err != nil || delay != want {
		t.Fatalf("Retry() = %v, %v; want %v, nil", delay, err, want)
	}
}

func queueExpectState(t *testing.T, q *queue, slug string, retained bool, retries int) {
	t.Helper()
	q.lock.Lock()
	defer q.lock.Unlock()
	if _, exists := q.requests[slug]; exists != retained {
		t.Errorf("request %q retained = %v, want %v", slug, exists, retained)
	}
	if got := q.rateLimiter.NumRequeues(slug); got != retries {
		t.Errorf("NumRequeues(%q) = %d, want %d", slug, got, retries)
	}
}

func queueCloseAndWait(q Queue) {
	q.Close()
	synctest.Wait()
}

func queueExpectReadyRetry(t *testing.T, q *queue, slug string) {
	t.Helper()
	q.lock.Lock()
	defer q.lock.Unlock()
	state := q.requests[slug]
	if state == nil || !state.retry || state.timer != nil || q.queue.Len() != 1 {
		t.Fatalf("expected an expired retry and one physical queue key for %q", slug)
	}
}

func TestQueueNewEventResetsBackoffAndReplacesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		start := time.Now()
		first := ReconcileRequest{TeamSlug: "team", CorrelationID: "first", TraceID: "first-trace"}
		latest := ReconcileRequest{TeamSlug: "team", CorrelationID: "latest", TraceID: "latest-trace"}

		queueAdd(t, q, first)
		queueExpectRequest(t, queueGetAsync(q), first)
		queueRetry(t, q, first, 10*time.Second)
		q.Done(first)
		queueExpectState(t, q, first.TeamSlug, true, 1)

		next := queueGetAsync(q)
		time.Sleep(time.Second)
		queueAdd(t, q, latest)
		queueExpectRequest(t, next, latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		queueRetry(t, q, latest, 10*time.Second)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, true, 1)
		next = queueGetAsync(q)

		other := ReconcileRequest{TeamSlug: "independent-team"}
		queueAdd(t, q, other)
		queueExpectRequest(t, next, other)
		q.Forget(other)
		q.Done(other)
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Fatalf("other team ran after %v, want 1s", elapsed)
		}
		next = queueGetAsync(q)

		time.Sleep(9 * time.Second)
		queueExpectBlocked(t, next) // The superseded deadline was t=10s.
		time.Sleep(time.Second)
		queueExpectRequest(t, next, latest)
		if elapsed := time.Since(start); elapsed != 11*time.Second {
			t.Fatalf("retry ran after %v, want 11s", elapsed)
		}
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		next = queueGetAsync(q)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
	})
}

func TestQueueSuccessCancelsEarlierRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		first := ReconcileRequest{TeamSlug: "team", CorrelationID: "failed"}
		latest := ReconcileRequest{TeamSlug: "team", CorrelationID: "succeeded", TraceID: "latest"}
		queueAdd(t, q, first)
		queueExpectRequest(t, queueGetAsync(q), first)
		queueRetry(t, q, first, 10*time.Second)
		q.Done(first)

		next := queueGetAsync(q)
		time.Sleep(time.Second)
		queueAdd(t, q, latest)
		queueExpectRequest(t, next, latest)
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)

		next = queueGetAsync(q)
		time.Sleep(9 * time.Second)
		queueExpectBlocked(t, next)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
	})
}

func TestQueueRetryReplacesPendingOrReadyTimer(t *testing.T) {
	for _, elapsed := range []time.Duration{time.Second, 10 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				q := NewQueue().(*queue)
				defer queueCloseAndWait(q)
				req := ReconcileRequest{TeamSlug: "team", CorrelationID: "retained"}
				queueRetry(t, q, req, 10*time.Second)
				time.Sleep(elapsed)
				synctest.Wait()
				queueRetry(t, q, req, 20*time.Second)
				next := queueGetAsync(q)
				queueExpectBlocked(t, next)
				time.Sleep(19 * time.Second)
				queueExpectBlocked(t, next)
				time.Sleep(time.Second)
				queueExpectRequest(t, next, req)
				q.Forget(req)
				q.Done(req)
				queueExpectState(t, q, req.TeamSlug, false, 0)
			})
		})
	}
}

func TestQueueNewEventDuringAttemptSurvivesCompletion(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "success"
		if failure {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				q := NewQueue().(*queue)
				defer queueCloseAndWait(q)
				first := ReconcileRequest{TeamSlug: "team", CorrelationID: "active"}
				middle := ReconcileRequest{TeamSlug: "team", CorrelationID: "superseded"}
				latest := ReconcileRequest{TeamSlug: "team", CorrelationID: "latest", TraceID: "latest-trace"}
				queueAdd(t, q, first)
				queueExpectRequest(t, queueGetAsync(q), first)
				queueAdd(t, q, middle)
				queueAdd(t, q, latest)
				next := queueGetAsync(q)
				queueExpectBlocked(t, next)

				other := ReconcileRequest{TeamSlug: "other"}
				queueAdd(t, q, other)
				queueExpectRequest(t, next, other)
				q.Forget(other)
				q.Done(other)
				next = queueGetAsync(q)
				queueExpectBlocked(t, next)

				retries := 0
				if failure {
					queueRetry(t, q, first, 10*time.Second)
					retries = 1
				} else {
					q.Forget(first)
				}
				queueExpectState(t, q, first.TeamSlug, true, retries)
				queueExpectBlocked(t, next)
				q.Done(first)
				queueExpectRequest(t, next, latest)
				queueExpectState(t, q, latest.TeamSlug, false, 0)

				next = queueGetAsync(q)
				time.Sleep(10 * time.Second)
				queueExpectBlocked(t, next)
				q.Forget(latest)
				q.Done(latest)
				queueExpectState(t, q, latest.TeamSlug, false, 0)
				time.Sleep(5 * time.Minute)
				queueExpectBlocked(t, next)
			})
		})
	}
}

func TestQueueRetainsOnlyPendingMetadata(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		for _, slug := range []string{"success", "not-found"} {
			req := ReconcileRequest{TeamSlug: slug, CorrelationID: "metadata"}
			queueRetry(t, q, req, 10*time.Second)
			queueExpectState(t, q, slug, true, 1)
			time.Sleep(10 * time.Second)
			queueExpectRequest(t, queueGetAsync(q), req)
			queueExpectState(t, q, slug, false, 1)
			q.Forget(req)
			queueExpectState(t, q, slug, false, 0)
			q.Done(req)
			queueExpectState(t, q, slug, false, 0)
		}

		req := ReconcileRequest{TeamSlug: "done-without-retry"}
		queueRetry(t, q, req, 10*time.Second)
		time.Sleep(10 * time.Second)
		queueExpectRequest(t, queueGetAsync(q), req)
		q.Done(req)
		queueExpectState(t, q, req.TeamSlug, false, 0)
		queueRetry(t, q, req, 10*time.Second)
		q.Forget(req)
		queueExpectState(t, q, req.TeamSlug, false, 0)
	})
}

func TestQueueForgetCancelsReadyRetryAndSkipsStaleKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		req := ReconcileRequest{TeamSlug: "team", CorrelationID: "old"}
		queueRetry(t, q, req, 10*time.Second)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		queueExpectState(t, q, req.TeamSlug, true, 1)
		queueExpectReadyRetry(t, q, req.TeamSlug)
		q.Forget(req)
		queueExpectState(t, q, req.TeamSlug, false, 0)
		next := queueGetAsync(q)
		queueExpectBlocked(t, next)

		latest := ReconcileRequest{TeamSlug: req.TeamSlug, CorrelationID: "new", TraceID: "new-trace"}
		queueAdd(t, q, latest)
		queueExpectRequest(t, next, latest)
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		next = queueGetAsync(q)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
	})
}

func TestQueueAddReplacesReadyRetryWithLatestEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		old := ReconcileRequest{TeamSlug: "team", CorrelationID: "old", TraceID: "old-trace"}
		latest := ReconcileRequest{TeamSlug: old.TeamSlug, CorrelationID: "latest", TraceID: "latest-trace"}
		queueRetry(t, q, old, 10*time.Second)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		queueExpectReadyRetry(t, q, old.TeamSlug)
		queueAdd(t, q, latest)
		q.lock.Lock()
		state := q.requests[old.TeamSlug]
		retryReady := state != nil && state.retry
		q.lock.Unlock()
		if retryReady {
			t.Error("Add() did not cancel the already-ready retry")
		}
		queueExpectRequest(t, queueGetAsync(q), latest)
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, old.TeamSlug, false, 0)
		next := queueGetAsync(q)
		queueExpectBlocked(t, next)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
	})
}

func TestQueueRecreatedSlugDoesNotInheritCanceledRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		old := ReconcileRequest{TeamSlug: "team", CorrelationID: "old", TraceID: "old-trace"}
		latest := ReconcileRequest{TeamSlug: old.TeamSlug, CorrelationID: "latest", TraceID: "latest-trace"}
		queueRetry(t, q, old, 10*time.Second)
		time.Sleep(time.Second)
		q.Forget(old)
		queueExpectState(t, q, old.TeamSlug, false, 0)

		queueAdd(t, q, latest)
		queueExpectRequest(t, queueGetAsync(q), latest)
		queueRetry(t, q, latest, 10*time.Second)
		q.Done(latest)
		next := queueGetAsync(q)
		time.Sleep(9 * time.Second)
		queueExpectBlocked(t, next)
		queueExpectState(t, q, latest.TeamSlug, true, 1)
		time.Sleep(time.Second)
		queueExpectRequest(t, next, latest)
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		next = queueGetAsync(q)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
	})
}

func TestQueueRecreatedSlugAfterStaleKeyClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		old := ReconcileRequest{TeamSlug: "team", CorrelationID: "old", TraceID: "old-trace"}
		latest := ReconcileRequest{TeamSlug: old.TeamSlug, CorrelationID: "latest", TraceID: "latest-trace"}
		queueRetry(t, q, old, 10*time.Second)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		queueExpectReadyRetry(t, q, old.TeamSlug)

		// Pause a worker after claiming its key, before reading request metadata.
		slug, shutdown := q.queue.Get()
		if shutdown || slug != old.TeamSlug {
			t.Fatalf("underlying Get() = %q, %v", slug, shutdown)
		}
		q.Forget(old)
		queueExpectState(t, q, old.TeamSlug, false, 0)
		queueAdd(t, q, latest)
		queueExpectState(t, q, latest.TeamSlug, true, 0)
		next := queueGetAsync(q)
		queueExpectBlocked(t, next)

		q.queue.Done(slug)
		queueExpectRequest(t, next, latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		q.Forget(latest)
		q.Done(latest)
		queueExpectState(t, q, latest.TeamSlug, false, 0)
		next = queueGetAsync(q)
		time.Sleep(5 * time.Minute)
		queueExpectBlocked(t, next)
	})
}

func TestQueueCloseReleasesTimersAndIdleState(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q := NewQueue().(*queue)
		defer queueCloseAndWait(q)
		delayed := ReconcileRequest{TeamSlug: "delayed"}
		active := ReconcileRequest{TeamSlug: "active"}
		queueAdd(t, q, active)
		queueExpectRequest(t, queueGetAsync(q), active)
		queueRetry(t, q, delayed, 10*time.Second)
		queueRetry(t, q, active, 10*time.Second)
		queueExpectState(t, q, delayed.TeamSlug, true, 1)
		queueExpectState(t, q, active.TeamSlug, true, 1)
		waiting := queueGetAsync(q)
		queueExpectBlocked(t, waiting)

		q.Close()
		synctest.Wait()
		select {
		case got := <-waiting:
			if !got.shutdown {
				t.Fatalf("Get() after Close() = %+v, want shutdown", got)
			}
		default:
			t.Fatal("Close() did not unblock Get()")
		}
		queueExpectState(t, q, delayed.TeamSlug, false, 0)
		queueExpectState(t, q, active.TeamSlug, false, 0)
		q.Forget(active)
		q.Done(active)
		queueExpectState(t, q, active.TeamSlug, false, 0)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		q.lock.Lock()
		defer q.lock.Unlock()
		if len(q.requests) != 0 {
			t.Fatalf("shutdown retained %d request entries", len(q.requests))
		}
	})
}
