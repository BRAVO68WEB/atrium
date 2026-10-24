package background

import "testing"

func TestGoFinishesBeforeWaitReturns(t *testing.T) {
	done := make(chan struct{})
	Go(func() { close(done) })
	Wait()
	select {
	case <-done:
	default:
		t.Fatal("Wait returned before the task finished")
	}
}
