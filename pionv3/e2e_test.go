// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

const (
	testMessage   = "Hello World"
	testTimeLimit = 10 * time.Second
	messageRetry  = 200 * time.Millisecond
)

var (
	errServerTimeout     = errors.New("waiting on serverReady err: timeout")
	errHookCiphersFailed = errors.New("hook failed to modify cipherlist")
	errHookAPLNFailed    = errors.New("hook failed to modify APLN extension")
)

func randomPort(tb testing.TB) int {
	tb.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	assert.NoError(tb, err, "failed to pick port")

	defer func() {
		_ = conn.Close()
	}()
	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		return addr.Port
	default:
		assert.Fail(tb, "failed to acquire port", "unknown addr type %T", addr)

		return 0
	}
}

func simpleReadWrite(
	ctx context.Context,
	errChan chan error,
	outChan chan string,
	conn io.ReadWriter,
	messageRecvCount *uint64,
) {
	go func() {
		buffer := make([]byte, len(testMessage))
		if _, err := io.ReadFull(conn, buffer); err != nil {
			errChan <- err

			return
		}
		atomic.AddUint64(messageRecvCount, 1)
		outChan <- string(buffer)
	}()
	if _, err := conn.Write([]byte(testMessage)); err != nil {
		errChan <- err

		return
	}
	ticker := time.NewTicker(messageRetry)
	defer ticker.Stop()
	for atomic.LoadUint64(messageRecvCount) != 2 {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type comm struct {
	ctx        context.Context
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption

	serverPort       int
	messageRecvCount uint64
	clientMutex      sync.Mutex
	clientConn       net.Conn
	clientDone       chan error
	serverMutex      sync.Mutex
	serverConn       net.Conn
	serverListener   net.Listener
	serverReady      chan struct{}
	serverDone       chan error
	errChan          chan error
	clientChan       chan string
	serverChan       chan string
	client           func(*comm)
	server           func(*comm)
}

func (c *comm) assert(t *testing.T) {
	t.Helper()

	go c.client(c)

	go c.server(c)

	defer func() {
		if c.clientConn != nil {
			assert.NoError(t, c.clientConn.Close())
		}
		if c.serverConn != nil {
			assert.NoError(t, c.serverConn.Close())
		}
		if c.serverListener != nil {
			assert.NoError(t, c.serverListener.Close())
		}
	}()

	seenClient, seenServer := false, false
	for {
		select {
		case err := <-c.errChan:
			assert.NoError(t, err)

			return
		case <-c.ctx.Done():
			assert.Failf(t, "Test timeout", "seenClient %t seenServer %t", seenClient, seenServer)

			return
		case clientMsg := <-c.clientChan:
			if !assert.Equal(t, testMessage, clientMsg) {
				return
			}

			seenClient = true
			if seenClient && seenServer {
				return
			}
		case serverMsg := <-c.serverChan:
			if !assert.Equal(t, testMessage, serverMsg) {
				return
			}

			seenServer = true
			if seenClient && seenServer {
				return
			}
		}
	}
}

func (c *comm) cleanup(t *testing.T) {
	t.Helper()

	clientDone, serverDone := false, false
	clientDoneCh, serverDoneCh := c.clientDone, c.serverDone
	timer := time.NewTimer(testTimeLimit)
	defer timer.Stop()

	for {
		select {
		case err := <-clientDoneCh:
			assert.NoError(t, err)
			clientDone = true
			clientDoneCh = nil
			if clientDone && serverDone {
				return
			}
		case err := <-serverDoneCh:
			assert.NoError(t, err)
			serverDone = true
			serverDoneCh = nil
			if clientDone && serverDone {
				return
			}
		case <-timer.C:
			assert.Fail(t, "Test timeout waiting for server shutdown")

			return
		}
	}
}

func clientPion(c *comm) {
	var result error
	defer func() {
		c.clientDone <- result
		close(c.clientDone)
	}()

	select {
	case <-c.serverReady:

	case <-time.After(time.Second):
		result = errServerTimeout
		c.errChan <- result

		return
	}

	c.clientMutex.Lock()
	defer c.clientMutex.Unlock()

	conn, err := dtls.DialWithOptions("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.clientOpts...,
	)
	if err != nil {
		result = err
		c.errChan <- result

		return
	}
	c.clientConn = conn

	if err := conn.HandshakeContext(c.ctx); err != nil {
		result = err
		c.errChan <- result

		return
	}

	simpleReadWrite(c.ctx, c.errChan, c.clientChan, c.clientConn, &c.messageRecvCount)
}

func serverPion(c *comm) {
	var result error
	defer func() {
		c.serverDone <- result
		close(c.serverDone)
	}()

	c.serverMutex.Lock()
	defer c.serverMutex.Unlock()

	var err error
	c.serverListener, err = dtls.ListenWithOptions(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.serverPort},
		c.serverOpts...,
	)
	if err != nil {
		result = err
		c.errChan <- result

		return
	}
	c.serverReady <- struct{}{}
	c.serverConn, err = c.serverListener.Accept()
	if err != nil {
		result = err
		c.errChan <- result

		return
	}

	dtlsConn, ok := c.serverConn.(*dtls.Conn)
	if ok {
		if err := dtlsConn.HandshakeContext(c.ctx); err != nil {
			result = err
			c.errChan <- result

			return
		}
	}

	simpleReadWrite(c.ctx, c.errChan, c.serverChan, c.serverConn, &c.messageRecvCount)
}

type dtlsTestOpts struct {
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption
}

type commOpts struct {
	timeout    time.Duration
	clientOpts []dtls.ClientOption
	serverOpts []dtls.ServerOption
}

func guardTest(t *testing.T) {
	t.Helper()
	lim := test.TimeOut(30 * time.Second)
	t.Cleanup(func() { lim.Stop() })
	t.Cleanup(test.CheckRoutines(t))
}

func runComm(t *testing.T, server, client func(*comm), cfg commOpts, opts ...dtlsTestOpts) {
	t.Helper()
	if cfg.timeout == 0 {
		cfg.timeout = testTimeLimit
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	for _, opt := range opts {
		cfg.clientOpts = append(cfg.clientOpts, opt.clientOpts...)
		cfg.serverOpts = append(cfg.serverOpts, opt.serverOpts...)
	}
	c := &comm{
		ctx: ctx, clientOpts: cfg.clientOpts, serverOpts: cfg.serverOpts,
		serverPort: randomPort(t), server: server, client: client,
		serverReady: make(chan struct{}, 1), serverDone: make(chan error, 1), clientDone: make(chan error, 1),
		errChan: make(chan error, 4), clientChan: make(chan string, 1), serverChan: make(chan string, 1),
	}
	defer c.cleanup(t)
	c.assert(t)
}

func withConnectionID(g func() []byte) dtlsTestOpts {
	return dtlsTestOpts{
		clientOpts: []dtls.ClientOption{dtls.WithConnectionIDGenerator(g)},
		serverOpts: []dtls.ServerOption{dtls.WithConnectionIDGenerator(g)},
	}
}

func testPionE2EWithCipherSuites(
	t *testing.T,
	server, client func(*comm),
	cipherSuites []dtls.CipherSuiteID,
	makeCert func(*testing.T) tls.Certificate,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)

	for _, cipherSuite := range cipherSuites {
		t.Run(cipherSuite.String(), func(t *testing.T) {
			cert := makeCert(t)
			clientOpts := []dtls.ClientOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
			}
			runComm(t, server, client, commOpts{
				clientOpts: clientOpts, serverOpts: serverOpts,
			}, opts...)
		})
	}
}

func selfSignedECDSACert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	assert.NoError(t, err)

	return cert
}

func selfSignedRSACert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	cert, err := selfsign.SelfSign(priv)
	assert.NoError(t, err)

	return cert
}

func testPionE2ESimple(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(
		t,
		server,
		client,
		[]dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
		selfSignedECDSACert,
		opts...,
	)
}

func testPionE2ESimpleRSA(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(
		t,
		server,
		client,
		[]dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		selfSignedRSACert,
		opts...,
	)
}

func testPionE2EChaCha20Poly1305(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(
		t,
		server,
		client,
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		selfSignedECDSACert,
		opts...,
	)
}

func testPionE2EChaCha20Poly1305RSA(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(
		t,
		server,
		client,
		[]dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		selfSignedRSACert,
		opts...,
	)
}

func testPionE2EPSK(
	t *testing.T,
	server, client func(*comm),
	cipherSuites []dtls.CipherSuiteID,
	pskHint []byte,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)
	for _, cipherSuite := range cipherSuites {
		t.Run(cipherSuite.String(), func(t *testing.T) {
			pskFunc := func([]byte) ([]byte, error) { return []byte{0xAB, 0xC1, 0x23}, nil }
			clientOpts := []dtls.ClientOption{dtls.WithPSKIdentityHint(pskHint), withPSK(func() ([]psk, error) {
				key, err := pskFunc(nil)

				return []psk{{Identity: pskHint, Key: key}}, err
			}, nil), dtls.WithCipherSuites(cipherSuite)}
			serverOpts := []dtls.ServerOption{withPSK(nil, func(identities [][]byte) (*psk, error) {
				key, err := pskFunc(identities[0])

				return &psk{Identity: identities[0], Key: key}, err
			}), dtls.WithCipherSuites(cipherSuite)}
			runComm(
				t,
				server,
				client,
				commOpts{
					clientOpts: clientOpts,
					serverOpts: serverOpts,
				},
				opts...,
			)
		})
	}
}

func testPionE2ESimplePSK(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EPSK(t, server, client, []dtls.CipherSuiteID{
		dtls.TLS_PSK_WITH_AES_128_CCM,
		dtls.TLS_PSK_WITH_AES_128_CCM_8,
		dtls.TLS_PSK_WITH_AES_256_CCM_8,
		dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	}, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, opts...)
}

func testPionE2EChaCha20Poly1305PSK(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EPSK(
		t,
		server,
		client,
		[]dtls.CipherSuiteID{dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256},
		[]byte{0x01, 0x02, 0x03},
		opts...,
	)
}

func testPionE2EMTUs(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)
	cipherSuite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	for _, mtu := range []int{10000, 1000, 100} {
		t.Run(fmt.Sprintf("MTU%d", mtu), func(t *testing.T) {
			cert := selfSignedECDSACert(t)
			clientOpts := []dtls.ClientOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMTU(mtu),
			}
			serverOpts := []dtls.ServerOption{
				dtls.WithCertificates(cert),
				dtls.WithCipherSuites(cipherSuite),
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMTU(mtu),
			}
			runComm(t, server, client, commOpts{
				timeout: 10 * time.Second, clientOpts: clientOpts, serverOpts: serverOpts,
			}, opts...)
		})
	}
}

func testPionE2ESimpleED25519(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EWithCipherSuites(t, server, client, []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}, func(t *testing.T) tls.Certificate {
		t.Helper()
		_, key, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)
		cert, err := selfsign.SelfSign(key)
		assert.NoError(t, err)

		return cert
	}, opts...)
}

func testPionE2EClientCert(
	t *testing.T,
	server, client func(*comm),
	cipherSuite dtls.CipherSuiteID,
	makeCert func(*testing.T) tls.Certificate,
	withClientCA bool,
	opts ...dtlsTestOpts,
) {
	t.Helper()
	guardTest(t)
	scert, ccert := makeCert(t), makeCert(t)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(ccert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(scert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
	}
	if withClientCA {
		clientCAs := x509.NewCertPool()
		caCert, err := x509.ParseCertificate(ccert.Certificate[0])
		assert.NoError(t, err)
		clientCAs.AddCert(caCert)
		serverOpts = append(serverOpts, dtls.WithClientCAs(clientCAs))
	}
	runComm(t, server, client, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
	}, opts...)
}

func testPionE2ESimpleED25519ClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(
		t,
		server,
		client,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		func(t *testing.T) tls.Certificate {
			t.Helper()
			_, key, err := ed25519.GenerateKey(rand.Reader)
			assert.NoError(t, err)
			cert, err := selfsign.SelfSign(key)
			assert.NoError(t, err)

			return cert
		},
		false,
		opts...,
	)
}

func testPionE2ESimpleECDSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(
		t,
		server,
		client,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		selfSignedECDSACert,
		true,
		opts...,
	)
}

func testPionE2ESimpleRSAClientCert(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	testPionE2EClientCert(
		t,
		server,
		client,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		selfSignedRSACert,
		false,
		opts...,
	)
}

func testPionE2ESimpleClientHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)

	t.Run("ClientHello hook", func(t *testing.T) {
		cert := selfSignedECDSACert(t)

		modifiedCipher := dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		supportedList := []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
			modifiedCipher,
		}

		clientOpts := []dtls.ClientOption{
			dtls.WithCertificates(cert),
			dtls.WithVerifyConnection(func(s *dtls.State) error {
				if s.CipherSuiteID != modifiedCipher {
					return errHookCiphersFailed
				}

				return nil
			}),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithClientHelloMessageHook(func(ch handshake.MessageClientHello) handshake.Message {
				ch.CipherSuiteIDs = []uint16{uint16(modifiedCipher)}

				return &ch
			}),
			dtls.WithInsecureSkipVerify(true),
		}

		serverOpts := []dtls.ServerOption{
			dtls.WithCertificates(cert),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithInsecureSkipVerify(true),
		}

		runComm(
			t,
			server,
			client,
			commOpts{
				clientOpts: clientOpts,
				serverOpts: serverOpts,
			},
			opts...,
		)
	})
}

func testPionE2ESimpleServerHelloHook(t *testing.T, server, client func(*comm), opts ...dtlsTestOpts) {
	t.Helper()
	guardTest(t)

	t.Run("ServerHello hook", func(t *testing.T) {
		cert := selfSignedECDSACert(t)

		supportedList := []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM}

		apln := "APLN"

		clientOpts := []dtls.ClientOption{
			dtls.WithCertificates(cert),
			dtls.WithSupportedProtocols(apln),
			dtls.WithVerifyConnection(func(s *dtls.State) error {
				if s.NegotiatedProtocol != apln {
					return errHookAPLNFailed
				}

				return nil
			}),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithInsecureSkipVerify(true),
		}

		serverOpts := []dtls.ServerOption{
			dtls.WithCertificates(cert),
			dtls.WithCipherSuites(supportedList...),
			dtls.WithServerHelloMessageHook(func(sh handshake.MessageServerHello) handshake.Message {
				sh.Extensions = append(sh.Extensions, &extension.ALPN{ProtocolNameList: []string{apln}})

				return &sh
			}),
			dtls.WithInsecureSkipVerify(true),
		}

		runComm(
			t,
			server,
			client,
			commOpts{
				clientOpts: clientOpts,
				serverOpts: serverOpts,
			},
			opts...,
		)
	})
}

type pionE2ETest func(*testing.T, func(*comm), func(*comm), ...dtlsTestOpts)

func TestPionV3E2E(t *testing.T) {
	tests := map[string]struct {
		run pionE2ETest
		cid bool
	}{
		"Simple":                     {run: testPionE2ESimple},
		"SimpleRSA":                  {run: testPionE2ESimpleRSA},
		"ChaCha20Poly1305":           {run: testPionE2EChaCha20Poly1305},
		"ChaCha20Poly1305RSA":        {run: testPionE2EChaCha20Poly1305RSA},
		"SimplePSK":                  {run: testPionE2ESimplePSK},
		"ChaCha20Poly1305PSK":        {run: testPionE2EChaCha20Poly1305PSK},
		"MTUs":                       {run: testPionE2EMTUs},
		"SimpleED25519":              {run: testPionE2ESimpleED25519},
		"SimpleED25519ClientCert":    {run: testPionE2ESimpleED25519ClientCert},
		"SimpleECDSAClientCert":      {run: testPionE2ESimpleECDSAClientCert},
		"SimpleRSAClientCert":        {run: testPionE2ESimpleRSAClientCert},
		"SimpleCID":                  {run: testPionE2ESimple, cid: true},
		"ChaCha20Poly1305CID":        {run: testPionE2EChaCha20Poly1305, cid: true},
		"ChaCha20Poly1305RSACID":     {run: testPionE2EChaCha20Poly1305RSA, cid: true},
		"SimplePSKCID":               {run: testPionE2ESimplePSK, cid: true},
		"ChaCha20Poly1305PSKCID":     {run: testPionE2EChaCha20Poly1305PSK, cid: true},
		"MTUsCID":                    {run: testPionE2EMTUs, cid: true},
		"SimpleED25519CID":           {run: testPionE2ESimpleED25519, cid: true},
		"SimpleED25519ClientCertCID": {run: testPionE2ESimpleED25519ClientCert, cid: true},
		"SimpleECDSAClientCertCID":   {run: testPionE2ESimpleECDSAClientCert, cid: true},
		"SimpleRSAClientCertCID":     {run: testPionE2ESimpleRSAClientCert, cid: true},
		"SimpleClientHelloHook":      {run: testPionE2ESimpleClientHelloHook},
		"SimpleServerHelloHook":      {run: testPionE2ESimpleServerHelloHook},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if test.cid {
				test.run(t, serverPion, clientPion, withConnectionID(dtls.RandomCIDGenerator(8)))

				return
			}
			test.run(t, serverPion, clientPion)
		})
	}
}

func testCertificateSignatureSchemes(
	t *testing.T,
	cert tls.Certificate,
	cipherSuite dtls.CipherSuiteID,
	schemes ...tls.SignatureScheme,
) {
	t.Helper()
	guardTest(t)
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(cert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(cert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	runComm(t, serverPion, clientPion, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
	})
}

func TestPionV3CertificateSignatureSchemesAllowed(t *testing.T) {
	testCertificateSignatureSchemes(
		t,
		selfSignedECDSACert(t),
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512,
	)
}

func TestPionV3CertificateSignatureSchemesRSA(t *testing.T) {
	testCertificateSignatureSchemes(
		t,
		selfSignedRSACert(t),
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.PSSWithSHA256,
		tls.PSSWithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA256,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA512,
	)
}

func TestPionV3CertificateSignatureSchemesClientCert(t *testing.T) {
	guardTest(t)

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)
	clientCert, err := selfsign.SelfSign(clientKey)
	assert.NoError(t, err)

	clientCAs := x509.NewCertPool()
	caCert, err := x509.ParseCertificate(clientCert.Certificate[0])
	assert.NoError(t, err)
	clientCAs.AddCert(caCert)

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithCertificateSignatureSchemes(tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384),
	}

	serverOpts := []dtls.ServerOption{
		dtls.WithClientCAs(clientCAs),
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAnyClientCert),
		dtls.WithCertificateSignatureSchemes(
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
		),
	}

	runComm(t, serverPion, clientPion, commOpts{
		clientOpts: clientOpts, serverOpts: serverOpts,
	})
}

func generateKey(t *testing.T, keyType string) (crypto.Signer, crypto.PublicKey) {
	t.Helper()
	var key crypto.Signer
	var err error
	switch keyType {
	case "ecdsa-p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		assert.FailNowf(t, "unknown key type", "unknown key type: %s", keyType)
	}
	assert.NoError(t, err)

	return key, key.Public()
}

func createCertChain(t *testing.T, leafKeyType string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, caPubKey := generateKey(t, leafKeyType)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPubKey, caKey)
	assert.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	assert.NoError(t, err)

	leafKey, leafPubKey := generateKey(t, leafKeyType)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	var leafCertDER []byte
	leafCertDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafPubKey, caKey)
	assert.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCertDER, caCertDER},
		PrivateKey:  leafKey,
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	return tlsCert, rootCAs
}

func assertHandshakeFailsWithOpts(
	t *testing.T,
	clientOpts []dtls.ClientOption,
	serverOpts []dtls.ServerOption,
	clientErrMsg string,
) {
	t.Helper()
	guardTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverPort := randomPort(t)

	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		listener, listenerErr := dtls.ListenWithOptions(
			"udp",
			&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
			serverOpts...,
		)
		if listenerErr != nil {
			serverDone <- listenerErr

			return
		}
		defer func() { _ = listener.Close() }()

		serverReady <- struct{}{}
		serverConn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr

			return
		}
		defer func() { _ = serverConn.Close() }()

		var handshakeErr error
		if dtlsConn, ok := serverConn.(*dtls.Conn); ok {
			handshakeErr = dtlsConn.HandshakeContext(ctx)
		}
		serverDone <- handshakeErr
	}()

	select {
	case <-serverReady:
	case <-time.After(time.Second):
		assert.FailNow(t, "server not ready in time")
	}

	conn, err := dtls.DialWithOptions("udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: serverPort},
		clientOpts...,
	)

	if err == nil && conn != nil {
		err = conn.HandshakeContext(ctx)
		_ = conn.Close()
	}

	assert.Error(t, err, clientErrMsg)

	select {
	case serverErr := <-serverDone:
		assert.Error(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Log("server did not complete in time")
	}
}

func testServerCertRejected(
	t *testing.T,
	keyType string,
	cipherSuite dtls.CipherSuiteID,
	schemes []tls.SignatureScheme,
	message string,
) {
	t.Helper()
	serverCert, serverRootCAs := createCertChain(t, keyType)
	clientCert := selfSignedECDSACert(t)
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithRootCAs(serverRootCAs),
		dtls.WithCertificateSignatureSchemes(schemes...),
	}
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(cipherSuite),
		dtls.WithInsecureSkipVerify(true),
	}
	assertHandshakeFailsWithOpts(t, clientOpts, serverOpts, message)
}

func TestPionV3CertificateSignatureSchemesServerCertRejected(t *testing.T) {
	testServerCertRejected(
		t,
		"ecdsa-p256",
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		[]tls.SignatureScheme{tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512},
		"expected handshake to fail with disallowed signature scheme",
	)
}

func TestPionV3CertificateSignatureSchemesClientCertRejected(t *testing.T) {
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientCert, clientRootCAs := createCertChain(t, "ecdsa-p256")

	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithInsecureSkipVerify(true),
	}

	serverOpts := []dtls.ServerOption{
		dtls.WithClientCAs(clientRootCAs),
		dtls.WithCertificates(serverCert),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
		dtls.WithCertificateSignatureSchemes(
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		),
	}

	assertHandshakeFailsWithOpts(
		t,
		clientOpts,
		serverOpts,
		"expected handshake to fail with disallowed client cert signature scheme",
	)
}

func TestPionV3CertificateSignatureSchemesRSAMismatch(t *testing.T) {
	testServerCertRejected(
		t,
		"rsa",
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		[]tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384},
		"expected handshake to fail with RSA cert but ECDSA-only schemes",
	)
}
