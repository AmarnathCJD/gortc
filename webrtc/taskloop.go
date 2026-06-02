// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

import (
	"context"
	"errors"
	"time"
)

var TaskloopErrClosed = errors.New("the agent is closed")

type taskloopTask struct {
	fn   func(context.Context)
	done chan struct{}
}

type TaskloopLoop struct {
	tasks        chan taskloopTask
	done         chan struct{}
	taskLoopDone chan struct{}
	err          AtomicErr
}

func TaskloopNew(onClose func()) *TaskloopLoop {
	l := &TaskloopLoop{
		tasks:        make(chan taskloopTask),
		done:         make(chan struct{}),
		taskLoopDone: make(chan struct{}),
	}

	go l.runLoop(onClose)

	return l
}

func (l *TaskloopLoop) runLoop(onClose func()) {
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

func (l *TaskloopLoop) Close() {
	if err := l.Err(); err != nil {
		return
	}

	l.err.Store(TaskloopErrClosed)

	close(l.done)
	<-l.taskLoopDone
}

func (l *TaskloopLoop) Run(ctx context.Context, t func(context.Context)) error {
	if err := l.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return TaskloopErrClosed
	case l.tasks <- taskloopTask{t, done}:
		<-done

		return nil
	}
}

func (l *TaskloopLoop) Done() <-chan struct{} {
	return l.done
}

func (l *TaskloopLoop) Err() error {
	select {
	case <-l.done:
		return TaskloopErrClosed
	default:
		return nil
	}
}

func (l *TaskloopLoop) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (l *TaskloopLoop) Value(any) any {
	return nil
}
