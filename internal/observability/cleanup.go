package observability

import (
	"context"
	"sync"
)

var cleanupWaitGroup sync.WaitGroup

func WaitForCleanup(ctx context.Context) {
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		cleanupWaitGroup.Wait()
	}()

	select {
	case <-cleanupDone:
		return
	case <-ctx.Done():
		return
	}
}