// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketedConnRead(t *testing.T) {
	connection, peer := newPacketedPipe(t)
	payload := []byte("datagram")
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(makePacketedBIOFrame(payload))
		writeDone <- err
	}()

	received := make([]byte, len(payload))
	read, err := connection.Read(received)
	require.NoError(t, err)
	require.Equal(t, len(payload), read)
	require.Equal(t, payload, received)
	require.NoError(t, <-writeDone)
}

func TestPacketedConnWrite(t *testing.T) {
	connection, peer := newPacketedPipe(t)
	payload := []byte("datagram")
	type writeResult struct {
		written int
		err     error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		written, err := connection.Write(payload)
		writeDone <- writeResult{written: written, err: err}
	}()

	received := make([]byte, packetedBIOHeaderSize+len(payload))
	_, err := io.ReadFull(peer, received)
	require.NoError(t, err)
	require.Equal(t, makePacketedBIOFrame(payload), received)

	result := <-writeDone
	require.NoError(t, result.err)
	require.Equal(t, len(payload), result.written)
}

func TestPacketedConnRejectsUnexpectedOpcode(t *testing.T) {
	connection, peer := newPacketedPipe(t)
	frame := makePacketedBIOFrame(nil)
	frame[0] = 'X'
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(frame)
		writeDone <- err
	}()

	read, err := connection.Read(make([]byte, 1))
	require.ErrorIs(t, err, errUnexpectedPacketedBIOOpcode)
	require.Zero(t, read)
	require.NoError(t, <-writeDone)
}

func TestPacketedConnShortBufferDrainsFrame(t *testing.T) {
	connection, peer := newPacketedPipe(t)
	firstPayload := []byte("too large")
	secondPayload := []byte("next")
	frames := append(makePacketedBIOFrame(firstPayload), makePacketedBIOFrame(secondPayload)...)
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(frames)
		writeDone <- err
	}()

	read, err := connection.Read(make([]byte, len(firstPayload)-1))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	require.Zero(t, read)

	received := make([]byte, len(secondPayload))
	read, err = connection.Read(received)
	require.NoError(t, err)
	require.Equal(t, len(secondPayload), read)
	require.Equal(t, secondPayload, received)
	require.NoError(t, <-writeDone)
}

func newPacketedPipe(t *testing.T) (*packetedConn, net.Conn) {
	t.Helper()

	local, peer := net.Pipe()
	t.Cleanup(func() {
		require.NoError(t, local.Close())
		require.NoError(t, peer.Close())
	})

	return &packetedConn{Conn: local}, peer
}

func makePacketedBIOFrame(payload []byte) []byte {
	frame := make([]byte, packetedBIOHeaderSize+len(payload))
	frame[0] = packetedBIOOpcode
	binary.BigEndian.PutUint32(frame[1:packetedBIOHeaderSize], uint32(len(payload))) //nolint:gosec
	copy(frame[packetedBIOHeaderSize:], payload)

	return frame
}
