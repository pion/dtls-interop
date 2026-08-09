// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const (
	boringSSLApplicationMessage = "hello"
	pionApplicationMessage      = "pion-to-boringssl"

	// One-record ACK: five-byte unified header, 18-byte ACK body, one-byte
	// inner content type, and a 16-byte AEAD tag. The DTLS 1.3 cipher suites
	// supported by Pion all use a 16-byte tag.
	dtls13SingleRecordACKDatagramSize = 40
	// One-record KeyUpdate: five-byte unified header, 13-byte handshake,
	// one-byte inner content type, and a 16-byte AEAD tag.
	dtls13KeyUpdateDatagramSize        = 35
	dtls13NewSessionTicketDatagramSize = 87
)

var errUnexpectedBoringSSLApplicationData = errors.New("unexpected BoringSSL application data")

type pionKeyUpdateFunc func(context.Context, *dtls.Conn) error

type pionDTLS13ExchangeOptions struct {
	updateKeys       pionKeyUpdateFunc
	peerKeyUpdate    bool
	newSessionTicket bool
}

func runPionDTLS13Client(
	ctx context.Context,
	connection *packetedConn,
	stdout io.Writer,
	options boringSSLProbeOptions,
) error {
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
		connection,
		stdout,
		"client",
		"processed BoringSSL's terminal ACK and received",
		pionDTLS13ExchangeOptions{
			updateKeys:    options.pionKeyUpdate,
			peerKeyUpdate: options.boringSSLKeyUpdate,
		},
	)
}

func runPionDTLS13Server(
	ctx context.Context,
	connection *packetedConn,
	stdout io.Writer,
	options boringSSLProbeOptions,
) error {
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

	return runPionDTLS13Exchange(
		ctx,
		server,
		connection,
		stdout,
		"server",
		"received",
		pionDTLS13ExchangeOptions{
			updateKeys:       options.pionKeyUpdate,
			peerKeyUpdate:    options.boringSSLKeyUpdate,
			newSessionTicket: true,
		},
	)
}

// nolint:cyclop
func runPionDTLS13Exchange(
	ctx context.Context,
	connection *dtls.Conn,
	packetedConnection *packetedConn,
	stdout io.Writer,
	role string,
	applicationRecordDescription string,
	options pionDTLS13ExchangeOptions,
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
	_, _ = fmt.Fprintf(stdout, "Pion DTLS 1.3 %s handshake completed\n", role)

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
	_, _ = fmt.Fprintf(stdout, "Pion %s application record %q\n", applicationRecordDescription, received)

	if options.newSessionTicket {
		if err := packetedConnection.waitForWriteSizeAfter(
			ctx,
			0,
			dtls13NewSessionTicketDatagramSize,
		); err != nil {
			return err
		}
	}
	if options.updateKeys != nil && options.newSessionTicket {
		if err := packetedConnection.advanceClock(ctx, time.Second); err != nil {
			return err
		}
	}
	var (
		keyUpdateDone      chan error
		keyUpdateCompleted bool
	)
	if options.updateKeys != nil {
		keyUpdateWriteBaseline := packetedConnection.writeCount.Load()
		keyUpdateDone = make(chan error, 1)
		go func() {
			keyUpdateDone <- options.updateKeys(ctx, connection)
		}()
		// UpdateKeys waits for the ACK, so wait separately until its KeyUpdate
		// is on the wire.
		completed, waitErr := waitForPionKeyUpdateWrite(
			ctx,
			packetedConnection,
			keyUpdateWriteBaseline,
			keyUpdateDone,
		)
		if waitErr != nil {
			return fmt.Errorf("update Pion DTLS 1.3 traffic keys: %w", waitErr)
		}
		keyUpdateCompleted = completed
	}
	if err := exchangePionApplicationData(
		ctx,
		connection,
		packetedConnection,
		stdout,
		options.peerKeyUpdate,
	); err != nil {
		return err
	}
	if options.updateKeys != nil {
		if err := packetedConnection.advanceClock(ctx, time.Second); err != nil {
			return err
		}
		if err := waitForPionKeyUpdateResult(keyUpdateCompleted, keyUpdateDone); err != nil {
			return fmt.Errorf("update Pion DTLS 1.3 traffic keys: %w", err)
		}
		_, _ = fmt.Fprintln(stdout, "Pion updated its traffic keys and requested a peer update")
		if err := exchangePionApplicationData(ctx, connection, packetedConnection, stdout, false); err != nil {
			return fmt.Errorf("exchange application data after KeyUpdate: %w", err)
		}
	}

	connectionClosed = true
	if err := connection.Close(); err != nil {
		return fmt.Errorf("close Pion DTLS connection: %w", err)
	}

	return nil
}

func exchangePionApplicationData(
	ctx context.Context,
	connection *dtls.Conn,
	packetedConnection *packetedConn,
	stdout io.Writer,
	waitForPeerKeyUpdateACK bool,
) error {
	pionPayload := []byte(pionApplicationMessage)
	peerKeyUpdateWriteBaseline := uint64(0)
	if waitForPeerKeyUpdateACK {
		peerKeyUpdateWriteBaseline = packetedConnection.writeCount.Load()
	}
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
	if waitForPeerKeyUpdateACK {
		if err = packetedConnection.waitForWriteSizeAfter(
			ctx,
			peerKeyUpdateWriteBaseline,
			dtls13SingleRecordACKDatagramSize,
		); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintln(stdout, "BoringSSL received and echoed Pion application record")

	return nil
}

func waitForPionKeyUpdateWrite(
	ctx context.Context,
	connection *packetedConn,
	after uint64,
	result <-chan error,
) (bool, error) {
	for !connection.hasWriteSizeAfter(after, dtls13KeyUpdateDatagramSize) {
		select {
		case <-connection.writeEvent:
		case err := <-result:
			return true, err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}

	return false, nil
}

func waitForPionKeyUpdateResult(completed bool, result <-chan error) error {
	if completed {
		return nil
	}

	return <-result
}
