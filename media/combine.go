package media

import (
	"context"
	"io"
)

// Loop repeats src forever (until the player is stopped or ctx is cancelled).
// Pre-encoded sources (FromOggOpus/FromIVF) cannot loop because their reader is
// consumed once; use a file/URL source to loop.
func Loop(src Source) Source {
	return &seqSource{tracks: src.Tracks(), next: loopProvider(src)}
}

// Concat plays the given sources back to back as a single source. All sources
// should provide the same set of tracks.
func Concat(srcs ...Source) Source {
	var tracks Track
	for _, s := range srcs {
		tracks |= s.Tracks()
	}

	return &seqSource{tracks: tracks, next: listProvider(srcs)}
}

func loopProvider(src Source) func() Source {
	return func() Source { return src }
}

func listProvider(srcs []Source) func() Source {
	i := 0

	return func() Source {
		if i >= len(srcs) {
			return nil
		}
		s := srcs[i]
		i++

		return s
	}
}

// seqSource yields successive sources from next() and concatenates their
// encoded streams behind a single set of readers.
type seqSource struct {
	tracks Track
	next   func() Source
}

func (s *seqSource) Tracks() Track { return s.tracks }

func (s *seqSource) Open(ctx context.Context) (*Streams, error) {
	first := s.next()
	if first == nil {
		return &Streams{}, nil
	}
	st, err := first.Open(ctx)
	if err != nil {
		return nil, err
	}

	cr := &chainReader{ctx: ctx, next: s.next, cur: st}
	out := &Streams{close: cr.close}
	// Chaining concatenates one track's readers. When both tracks are present
	// we chain audio (the master clock) and pass the first source's video
	// through without re-chaining, since coordinating two independent EOF
	// boundaries across sources is not supported.
	if s.tracks.Has(TrackAudio) {
		out.Audio = &trackReader{chain: cr, pick: pickAudio}
	} else if s.tracks.Has(TrackVideo) {
		out.Video = &trackReader{chain: cr, pick: pickVideo}
	}

	return out, nil
}

func pickAudio(st *Streams) io.Reader { return st.Audio }
func pickVideo(st *Streams) io.Reader { return st.Video }

type chainReader struct {
	ctx  context.Context
	next func() Source
	cur  *Streams
}

func (c *chainReader) advance() bool {
	if c.cur != nil {
		_ = c.cur.Close()
	}
	src := c.next()
	if src == nil {
		c.cur = nil

		return false
	}
	st, err := src.Open(c.ctx)
	if err != nil {
		c.cur = nil

		return false
	}
	c.cur = st

	return true
}

func (c *chainReader) close() error {
	if c.cur != nil {
		return c.cur.Close()
	}

	return nil
}

type trackReader struct {
	chain *chainReader
	pick  func(*Streams) io.Reader
}

func (t *trackReader) Read(p []byte) (int, error) {
	for {
		if t.chain.cur == nil {
			return 0, io.EOF
		}
		r := t.pick(t.chain.cur)
		if r == nil {
			if !t.chain.advance() {
				return 0, io.EOF
			}

			continue
		}
		n, err := r.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			if !t.chain.advance() {
				return 0, io.EOF
			}

			continue
		}
		if err != nil {
			return 0, err
		}
	}
}
