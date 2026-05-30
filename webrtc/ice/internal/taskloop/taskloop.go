package taskloop

import (
	"context"
	"errors"
	"time"

	"github.com/amarnathcjd/gortc/webrtc"
)

var ErrClosed = errors.New("the agent is closed")

type task struct {
	fn   func(context.Context)
	done chan struct{}
}

type Loop struct {
	tasks        chan task
	done         chan struct{}
	taskLoopDone chan struct{}
	err          webrtc.AtomicErr
}

func New(onClose func()) *Loop {
	l := &Loop{
		tasks:        make(chan task),
		done:         make(chan struct{}),
		taskLoopDone: make(chan struct{}),
	}

	go l.runLoop(onClose)

	return l
}

func (l *Loop) runLoop(onClose func()) {
	defer func() {
		onClose()
		close(l.taskLoopDone)
	}()

	for {
		select {
		case <-l.done:
			return
		case t := <-l.tasks:
			t.fn(l)
			close(t.done)
		}
	}
}

func (l *Loop) Close() {
	if err := l.Err(); err != nil {
		return
	}

	l.err.Store(ErrClosed)

	close(l.done)
	<-l.taskLoopDone
}

func (l *Loop) Run(ctx context.Context, t func(context.Context)) error {
	if err := l.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return ErrClosed
	case l.tasks <- task{t, done}:
		<-done

		return nil
	}
}

func (l *Loop) Done() <-chan struct{} {
	return l.done
}

func (l *Loop) Err() error {
	select {
	case <-l.done:
		return ErrClosed
	default:
		return nil
	}
}

func (l *Loop) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (l *Loop) Value(any) any {
	return nil
}
