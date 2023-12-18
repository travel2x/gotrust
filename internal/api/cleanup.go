package api

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
	case <-ctx.Done():
		return

	case <-cleanupDone:
		return
	}
}
