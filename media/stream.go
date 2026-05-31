// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"context"
	"fmt"
	"io"
	"sync"
)

type AVSender interface {
	Sender
	VideoSender
}

// Stream opens src and streams its audio/video to send until the source ends
// or ctx is cancelled. Missing tracks are skipped.
func Stream(ctx context.Context, send AVSender, audioSSRC, videoSSRC uint32, src Source) error {
	streams, err := src.Open(ctx)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer streams.Close()

	var wg sync.WaitGroup
	var audioErr, videoErr error

	if streams.Audio != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			audioErr = StreamOggOpus(send, audioSSRC, streams.Audio)
			_, _ = io.Copy(io.Discard, streams.Audio)
		}()
	}
	if streams.Video != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			videoErr = StreamIVF(send, videoSSRC, streams.Video)
			_, _ = io.Copy(io.Discard, streams.Video)
		}()
	}

	wg.Wait()

	if audioErr != nil {
		return fmt.Errorf("audio stream: %w", audioErr)
	}
	if videoErr != nil {
		return fmt.Errorf("video stream: %w", videoErr)
	}

	return nil
}

func streamControlled(ctx context.Context, send AVSender, audioSSRC, videoSSRC uint32, src Source, ctrl *playControl) error {
	streams, err := src.Open(ctx)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}

	go func() {
		<-ctx.Done()
		ctrl.stop()
	}()

	return runStreams(streams, send, audioSSRC, videoSSRC, ctrl)
}

func runStreams(streams *Streams, send AVSender, audioSSRC, videoSSRC uint32, ctrl *playControl) error {
	defer streams.Close()

	var wg sync.WaitGroup
	var audioErr, videoErr error

	if streams.Audio != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			audioErr = streamOggOpus(send, audioSSRC, streams.Audio, ctrl)
			_, _ = io.Copy(io.Discard, streams.Audio)
		}()
	}
	if streams.Video != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			videoErr = streamIVF(send, videoSSRC, streams.Video, ctrl)
			_, _ = io.Copy(io.Discard, streams.Video)
		}()
	}

	wg.Wait()

	if ctrl.isStopped() {
		return nil
	}
	if audioErr != nil {
		return fmt.Errorf("audio stream: %w", audioErr)
	}
	if videoErr != nil {
		return fmt.Errorf("video stream: %w", videoErr)
	}

	return nil
}
