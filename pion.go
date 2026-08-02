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
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const (
	boringSSLApplicationMessage = "hello"
	pionApplicationMessage      = "pion-to-boringssl"
)

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

	return runPionDTLS13Exchange(
		ctx,
		client,
		stdout,
		"client",
		"processed BoringSSL's terminal ACK and received",
	)
}

func runPionDTLS13Server(ctx context.Context, connection net.Conn, stdout io.Writer) error {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return fmt.Errorf("generate Pion DTLS 1.3 server certificate: %w", err)
	}

	server, err := dtls.ServerWithOptions(
		dtlsnet.PacketConnFromConn(connection),
		connection.RemoteAddr(),
		dtls.WithCertificates(certificate),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithInsecureSkipVerifyHello(true),
		dtls.WithEllipticCurves(elliptic.X25519),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	)
	if err != nil {
		return fmt.Errorf("create Pion DTLS 1.3 server: %w", err)
	}

	return runPionDTLS13Exchange(ctx, server, stdout, "server", "received")
}

// nolint:cyclop
func runPionDTLS13Exchange(
	ctx context.Context,
	connection *dtls.Conn,
	stdout io.Writer,
	role string,
	applicationRecordDescription string,
) error {
	connectionClosed := false
	defer func() {
		if !connectionClosed {
			_ = connection.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set Pion DTLS deadline: %w", err)
		}
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("pion DTLS 1.3 handshake: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "PASS %s: Pion DTLS 1.3 %s handshake completed\n", boringSSL13Mode, role)

	received := make([]byte, len(boringSSLApplicationMessage))
	if _, err := io.ReadFull(connection, received); err != nil {
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
	_, _ = fmt.Fprintf(
		stdout,
		"PASS %s: Pion %s application record %q\n",
		boringSSL13Mode,
		applicationRecordDescription,
		received,
	)

	pionPayload := []byte(pionApplicationMessage)
	written, err := connection.Write(pionPayload)
	if err != nil {
		return fmt.Errorf("write Pion application record to BoringSSL: %w", err)
	}
	if written != len(pionPayload) {
		return fmt.Errorf("write Pion application record to BoringSSL: %w", io.ErrShortWrite)
	}

	echoed := make([]byte, len(pionPayload))
	if _, err = io.ReadFull(connection, echoed); err != nil {
		return fmt.Errorf("read BoringSSL echo of Pion application record: %w", err)
	}
	for index := range pionPayload {
		pionPayload[index] ^= 0xff
	}
	if !bytes.Equal(echoed, pionPayload) {
		return fmt.Errorf("unexpected BoringSSL echo: got %x, want %x", echoed, pionPayload) //nolint:err113
	}
	_, _ = fmt.Fprintf(stdout, "PASS %s: BoringSSL received and echoed Pion application record\n", boringSSL13Mode)

	connectionClosed = true
	if err = connection.Close(); err != nil {
		return fmt.Errorf("close Pion DTLS connection: %w", err)
	}

	return nil
}
