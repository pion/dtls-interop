// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

func TestPionV3ReplayProtection(t *testing.T) {
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	c0, c1 := packetPipe()
	c2, c3 := packetPipe()
	conn := []*packetTestConn{c0, c1, c2, c3}

	var wgRoutines sync.WaitGroup
	var cntReplays int32 = 1

	ctxReplayDone, replayDone := context.WithCancel(context.Background())

	replaySendDone := func() {
		cnt := atomic.AddInt32(&cntReplays, -1)
		if cnt == 0 {
			replayDone()
		}
	}

	replayer := func(ca, cb *packetTestConn) {
		defer wgRoutines.Done()

		for {
			b := make([]byte, 2048)
			n, rerr := ca.Read(b)
			if rerr != nil {
				return
			}
			_, werr := cb.Write(b[:n])
			assert.NoError(t, werr)

			atomic.AddInt32(&cntReplays, 1)
			go func() {
				defer replaySendDone()

				time.Sleep(time.Millisecond)
				_, werr := cb.Write(b[:n])
				assert.NoError(t, werr)
			}()
		}
	}
	wgRoutines.Add(2)
	go replayer(conn[1], conn[2])
	go replayer(conn[2], conn[1])

	ca, cb, err := pipeConn(conn[0], conn[3])
	assert.NoError(t, err)

	const numMsgs = 10

	var received [2][][]byte
	for i, c := range []net.Conn{ca, cb} {
		wgRoutines.Add(1)
		atomic.AddInt32(&cntReplays, 1)
		var lastMsgDone sync.Once
		go func() {
			defer wgRoutines.Done()
			for {
				b := make([]byte, 2048)
				n, rerr := c.Read(b)
				if rerr != nil {
					return
				}
				received[i] = append(received[i], b[:n])
				if b[0] == numMsgs-1 {
					lastMsgDone.Do(func() {
						defer replaySendDone()
					})
				}
			}
		}()
	}

	var sent [][]byte
	for i := range numMsgs {
		data := []byte{byte(i)}
		sent = append(sent, data)
		_, werr := ca.Write(data)
		assert.NoError(t, werr)
		_, werr = cb.Write(data)
		assert.NoError(t, werr)
	}

	replaySendDone()
	<-ctxReplayDone.Done()
	time.Sleep(10 * time.Millisecond)

	for i := range 4 {
		assert.NoError(t, conn[i].Close())
	}
	assert.NoError(t, ca.Close())
	assert.NoError(t, cb.Close())
	wgRoutines.Wait()

	for _, r := range received {
		assert.Equal(t, sent, r)
	}
}
