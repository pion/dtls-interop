// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/dpipe"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func marshalTestRecord(header recordlayer.Header, content protocol.Content) ([]byte, error) {
	record := recordlayer.RecordLayer{Header: header, Content: content}
	return record.Marshal()
}

func (c *packetTestConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)

	return n, c.remoteAddr, err
}

func (c *packetTestConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func (c *packetTestConn) RemoteAddr() net.Addr { return c.remoteAddr }

func packetPipe() (*packetTestConn, *packetTestConn) {
	a, b := dpipe.Pipe()

	return &packetTestConn{Conn: a, remoteAddr: b.LocalAddr()},
		&packetTestConn{Conn: b, remoteAddr: a.LocalAddr()}
}

func pipeMemory() (*dtls.Conn, *dtls.Conn, error) {
	ca, cb := packetPipe()

	return pipeConn(ca, cb)
}

func pipeConn(ca, cb net.PacketConn) (*dtls.Conn, *dtls.Conn, error) {
	type result struct {
		c   *dtls.Conn
		err error
	}

	resultCh := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		client, err := testClient(
			ctx,
			ca,
			cb.LocalAddr(),
			[]dtls.ClientOption{dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80)},
			true,
		)
		resultCh <- result{client, err}
	}()

	server, err := testServer(
		ctx,
		cb,
		ca.LocalAddr(),
		[]dtls.ServerOption{dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80)},
		true,
	)
	if err != nil {
		if res := <-resultCh; res.c != nil {
			_ = res.c.Close()
		}

		return nil, nil, err
	}

	res := <-resultCh
	if res.err != nil {
		_ = server.Close()

		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(
	ctx context.Context,
	pktConn net.PacketConn,
	rAddr net.Addr,
	opts []dtls.ClientOption,
	generateCertificate bool,
) (
	*dtls.Conn,
	error,
) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, dtls.WithCertificates(clientCert))
	}
	opts = append(opts, dtls.WithInsecureSkipVerify(true))
	conn, err := dtls.ClientWithOptions(pktConn, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func testServer(
	ctx context.Context,
	transport net.PacketConn,
	rAddr net.Addr,
	opts []dtls.ServerOption,
	generateCertificate bool,
) (
	*dtls.Conn,
	error,
) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		opts = append(opts, dtls.WithCertificates(serverCert))
	}
	conn, err := dtls.ServerWithOptions(transport, rAddr, opts...)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func handshakePair(
	t *testing.T,
	clientOpts []dtls.ClientOption,
	serverOpts []dtls.ServerOption,
) (
	handshakeResult,
	handshakeResult,
) {
	t.Helper()
	ca, cb := packetPipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})
	clientCh := make(chan handshakeResult)
	go func() {
		client, err := dtls.ClientWithOptions(ca, ca.RemoteAddr(), clientOpts...)
		var handshakeErr error
		if err == nil {
			handshakeErr = client.Handshake()
		}
		clientCh <- handshakeResult{client, err, handshakeErr}
	}()
	server, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(), serverOpts...)
	var handshakeErr error
	if err == nil {
		handshakeErr = server.Handshake()
	}
	clientResult := <-clientCh
	serverResult := handshakeResult{server, err, handshakeErr}
	t.Cleanup(func() {
		if clientResult.conn != nil {
			_ = clientResult.conn.Close()
		}
		if serverResult.conn != nil {
			_ = serverResult.conn.Close()
		}
	})

	return clientResult, serverResult
}

func sendClientHello(
	cookie []byte,
	ca net.Conn,
	sequenceNumber uint64,
	extensions []extension.Extension,
	cipherSuiteIDsOverride ...uint16,
) error {
	cipherSuites := cipherSuiteIDsOverride
	if len(cipherSuites) == 0 {
		cipherSuites = []uint16{
			uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			uint16(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
		}
	}

	clientHello := handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		Cookie:             cookie,
		CipherSuiteIDs:     cipherSuites,
		CompressionMethods: []*protocol.CompressionMethod{protocol.CompressionMethods()[0]},
		Extensions:         extensions,
	}

	packet, err := marshalTestRecord(recordlayer.Header{
		Version:        protocol.Version1_2,
		SequenceNumber: sequenceNumber,
	}, &handshake.Handshake{
		Header: handshake.Header{
			MessageSequence: uint16(sequenceNumber),
		},
		Message: &clientHello,
	})
	if err != nil {
		return err
	}

	if _, err = ca.Write(packet); err != nil {
		return err
	}

	return nil
}

func unmarshalHandshakeRecord(t *testing.T, raw []byte) (recordlayer.Header, *handshake.Handshake) {
	t.Helper()

	header, parseErr := parseRecord(raw, 0)
	require.NoError(t, parseErr)
	require.Equal(t, protocol.ContentTypeHandshake, header.ContentType)
	require.GreaterOrEqual(t, len(raw), header.Size())

	var content handshake.Handshake
	require.NoError(t, content.Unmarshal(raw[header.Size():]))

	return header, &content
}

func unmarshalAlertRecord(t *testing.T, raw []byte) *alert.Alert {
	t.Helper()

	header, parseErr := parseRecord(raw, 0)
	assert.NoError(t, parseErr)
	assert.Equal(t, protocol.ContentTypeAlert, header.ContentType)
	assert.GreaterOrEqual(t, len(raw), header.Size())

	var content alert.Alert
	assert.NoError(t, content.Unmarshal(raw[header.Size():]))

	return &content
}

func deliverNextBridgePacket(t *testing.T, br *test.Bridge) {
	t.Helper()

	require.Eventually(t, func() bool {
		return br.Tick() > 0
	}, time.Second, time.Millisecond, "timed out delivering bridge packet")
}

func waitForBridgeHandshakes(
	t *testing.T,
	ctx context.Context,
	br *test.Bridge,
	results <-chan error,
) {
	t.Helper()

	for completed := 0; completed < 2; {
		br.Tick()
		select {
		case err := <-results:
			require.NoError(t, err)
			completed++
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func waitForBridgePacket(t *testing.T, br *test.Bridge, fromID int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for br.Len(fromID) == 0 {
		if time.Now().After(deadline) {
			require.FailNow(t, "timed out waiting for bridge packet", "from endpoint %d", fromID)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertDTLSApplicationDataOverBridge(
	t *testing.T,
	br *test.Bridge,
	sender, receiver *dtls.Conn,
	payload []byte,
) {
	t.Helper()

	type readResult struct {
		data []byte
		err  error
	}
	result := make(chan readResult, 1)
	go func() {
		buf := make([]byte, len(payload))
		n, readErr := io.ReadFull(receiver, buf)
		result <- readResult{data: buf[:n], err: readErr}
	}()

	n, err := sender.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		br.Tick()
		select {
		case read := <-result:
			require.NoError(t, read.err)
			assert.Equal(t, payload, read.data)

			return
		case <-deadline.C:
			require.FailNow(t, "timed out reading application data after HRR")
		case <-time.After(time.Millisecond):
		}
	}
}

func (r *testRecord) Marshal() ([]byte, error) {
	return marshalTestRecord(r.Header, r.Content)
}

var (
	errTestPSKInvalidIdentity  = errors.New("TestPSK: Server got invalid identity")
	errPSKRejected             = errors.New("psk Rejected")
	errNotExpectedChain        = errors.New("not expected chain")
	errExpectedChain           = errors.New("expected chain")
	errWrongCert               = errors.New("wrong cert")
	errConnectionAttemptFailed = errors.New("connection attempt failed")
)

type packetTestConn struct {
	net.Conn
	remoteAddr net.Addr
}
type handshakeResult struct {
	conn           *dtls.Conn
	configErr      error
	handshakeError error
}
type testRecord struct {
	Header  recordlayer.Header
	Content protocol.Content
}
type srtpConfigurationTest struct {
	Name                          string
	ClientSRTP                    []dtls.SRTPProtectionProfile
	ServerSRTP                    []dtls.SRTPProtectionProfile
	ClientSRTPMasterKeyIdentifier []byte
	ServerSRTPMasterKeyIdentifier []byte
	ExpectedClientMKI             []byte
	ExpectedServerMKI             []byte
	ExpectedProfile               dtls.SRTPProtectionProfile
	WantClientError               error
	WantServerError               error
}
type connWithCallback struct {
	*packetTestConn
	onWrite func([]byte)
}

func (c *connWithCallback) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.onWrite(b)

	return c.packetTestConn.WriteTo(b, addr)
}

var errExample = errors.New("example error")

const renegotiationInfoSCSV uint16 = 0x00ff

type expectedTextError string

func (e expectedTextError) Error() string { return string(e) }
func assertInteropError(t *testing.T, actual, expected error, msg ...any) bool {
	t.Helper()
	var text expectedTextError
	if errors.As(expected, &text) {
		if errorTreeContains(actual, string(text)) {
			return true
		}

		return assert.Fail(t, fmt.Sprintf("expected error %q in error chain, got %v", text, actual), msg...)
	}

	return assert.ErrorIs(t, actual, expected, msg...)
}

func errorTreeContains(err error, message string) bool {
	if err == nil {
		return false
	}
	if err.Error() == message {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if errorTreeContains(cause, message) {
				return true
			}
		}
	}

	return errorTreeContains(errors.Unwrap(err), message)
}

func assertPionPayload(t *testing.T, sender, receiver *dtls.Conn, payload []byte) {
	t.Helper()
	require.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	n, err := sender.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	buf := make([]byte, len(payload))
	n, err = receiver.Read(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
}

func connectionState(t *testing.T, conn *dtls.Conn) *dtls.State {
	t.Helper()
	state, ok := conn.ConnectionState()
	require.True(t, ok)

	return &state
}

func signatureSchemeIDs(algorithms []signaturehash.Algorithm) []uint16 {
	schemes := make([]uint16, len(algorithms))
	for i, algorithm := range algorithms {
		schemes[i] = uint16(algorithm.Hash)<<8 | uint16(algorithm.Signature)
	}

	return schemes
}
