// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/pion/dtls/v3"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const boringSSLApplicationMessage = "hello"

var errUnexpectedBoringSSLApplicationData = errors.New("unexpected BoringSSL application data")

func runPionDTLS13Client(ctx context.Context, connection net.Conn, stdout io.Writer) error {
	client, err := dtls.ClientWithOptions(
		dtlsnet.PacketConnFromConn(connection),
		connection.RemoteAddr(),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	)
	if err != nil {
		return fmt.Errorf("create Pion DTLS 1.3 client: %w", err)
	}
	clientClosed := false
	defer func() {
		if !clientClosed {
			_ = client.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err = client.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set Pion DTLS deadline: %w", err)
		}
	}
	if err = client.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("pion DTLS 1.3 handshake: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "PASS %s: Pion DTLS 1.3 handshake completed\n", boringSSL13Mode)

	received := make([]byte, len(boringSSLApplicationMessage))
	if _, err = io.ReadFull(client, received); err != nil {
		return fmt.Errorf("read BoringSSL application record with Pion: %w", err)
	}
	if !bytes.Equal(received, []byte(boringSSLApplicationMessage)) {
		return fmt.Errorf(
			"%w: got %q, want %q",
			errUnexpectedBoringSSLApplicationData,
			received,
			boringSSLApplicationMessage,
		)
	}
	_, _ = fmt.Fprintf(stdout, "PASS %s: Pion received application record %q\n", boringSSL13Mode, received)

	clientClosed = true
	if err = client.Close(); err != nil {
		return fmt.Errorf("close Pion DTLS connection: %w", err)
	}

	return nil
}
