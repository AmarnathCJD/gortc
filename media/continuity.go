package media

import (
	"math/rand"
	"sync"
)

type rtpCursor struct {
	seq uint16
	ts  uint32
}

var (
	contMu  sync.Mutex
	cursors = map[uint32]*rtpCursor{}
)

func nextCursor(ssrc uint32) *rtpCursor {
	contMu.Lock()
	defer contMu.Unlock()
	c, ok := cursors[ssrc]
	if !ok {
		c = &rtpCursor{seq: uint16(rand.Uint32()), ts: rand.Uint32()}
		cursors[ssrc] = c
	}

	return c
}

func loadCursor(ssrc uint32) (c *rtpCursor, seq uint16, ts uint32) {
	c = nextCursor(ssrc)
	contMu.Lock()
	seq, ts = c.seq, c.ts
	contMu.Unlock()

	return
}

func saveCursor(c *rtpCursor, seq uint16, ts uint32) {
	contMu.Lock()
	c.seq, c.ts = seq, ts
	contMu.Unlock()
}
