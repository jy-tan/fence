//go:build linux

package main

import (
	"testing"
	"time"
)

func TestResizeDebouncer_CoalescesSignals(t *testing.T) {
	debouncer := newResizeDebouncer(10 * time.Millisecond)
	defer debouncer.Stop()

	debouncer.Queue()
	firstCh := debouncer.Channel()
	if firstCh == nil {
		t.Fatal("expected debounce channel after first queue")
	}

	debouncer.Queue()
	if debouncer.Channel() != firstCh {
		t.Fatal("expected second queue to reuse pending debounce channel")
	}

	select {
	case <-firstCh:
		debouncer.MarkHandled()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for debounced signal")
	}

	if debouncer.Channel() != nil {
		t.Fatal("expected debounce channel to reset after mark handled")
	}
}
