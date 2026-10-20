// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	cryptoElliptic "crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPionV4StressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	t.Helper()

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, ca.Close())
		assert.NoError(t, cb.Close())
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	assert.NoError(t, test.StressDuplex(ca, cb, opt))
}

func TestPionV4RoutineLeakOnClose(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)

	_, err = ca.Write(make([]byte, 100))
	assert.NoError(t, err)
	assert.NoError(t, cb.Close())
	assert.NoError(t, ca.Close())
	// Packet is sent, but not read.
	// inboundLoop routine should not be leaked.
}

func TestPionV4ReadWriteDeadline(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var netErr net.Error

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)
	assert.NoError(t, ca.SetDeadline(time.Unix(0, 1)))

	n, werr := ca.Write(make([]byte, 100))
	assert.ErrorAs(t, werr, &netErr, "Write must return net.Error")
	assert.Zero(t, n)
	assert.True(t, netErr.Timeout(), "Deadline exceeded Write must return Timeout")
	assert.True(t, netErr.Temporary(), "Deadline exceeded Write must return Temporary") //nolint:staticcheck

	_, rerr := ca.Read(make([]byte, 100))
	assert.ErrorAs(t, rerr, &netErr, "Read must return net.Error")
	assert.True(t, netErr.Timeout(), "Deadline exceeded Read must return Timeout")
	assert.True(t, netErr.Temporary(), "Deadline exceeded Read must return Temporary") //nolint:staticcheck
	assert.NoError(t, ca.SetDeadline(time.Time{}))
	assert.NoError(t, ca.Close())
	assert.NoError(t, cb.Close())

	_, err = ca.Write(make([]byte, 100))
	assertInteropError(t, err, dtls.ErrConnClosed)
	_, err = ca.Read(make([]byte, 100))
	assertInteropError(t, err, io.EOF)
}

func TestPionV4WriteReturnsZeroOnTransportError(t *testing.T) {
	caRaw, cbRaw := packetPipe()
	caTransport := &writeErrorConn{packetTestConn: caRaw}
	ca, cb, err := pipeConn(caTransport, cbRaw)
	require.NoError(t, err)
	defer func() {
		caTransport.fail.Store(false)
		require.NoError(t, ca.Close())
		require.NoError(t, cb.Close())
	}()

	caTransport.fail.Store(true)
	n, err := ca.Write([]byte("application data"))
	requireInteropError(t, err, errWriteFailed)
	require.Zero(t, n)
}

func TestPionV4HandshakeWithAlert(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cases := map[string]struct {
		serverOpts []dtls.ServerOption
		clientOpts []dtls.ClientOption
		errServer  error
		errClient  error
	}{
		"CipherSuiteNoIntersection": {
			serverOpts: []dtls.ServerOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			},
			clientOpts: []dtls.ClientOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
			},
			errServer: expectedTextError("client+server do not support any shared cipher suites"),
			errClient: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
		},
		"SignatureSchemesNoIntersection": {
			serverOpts: []dtls.ServerOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			},
			clientOpts: []dtls.ClientOption{
				dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithSignatureSchemes(tls.ECDSAWithP521AndSHA512),
			},
			errServer: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			errClient: expectedTextError("connection can not be created, no SignatureScheme satisfy this Config"),
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			clientErr := make(chan error, 1)

			ca, cb := packetPipe()
			go func() {
				_, err := testClient(ctx, ca, ca.RemoteAddr(), testCase.clientOpts, true)
				clientErr <- err
			}()

			_, errServer := testServer(ctx, cb, cb.RemoteAddr(), testCase.serverOpts, true)
			assertInteropError(t, errServer, testCase.errServer)
			assertInteropError(t, <-clientErr, testCase.errClient)
		})
	}
}

func TestPionV4HandshakeWithInvalidRecord(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		c   *dtls.Conn
		err error
	}
	clientErr := make(chan result, 1)
	ca, cb := packetPipe()
	caWithInvalidRecord := &connWithCallback{packetTestConn: ca}

	var msgSeq atomic.Int32
	// Send invalid record after first message
	caWithInvalidRecord.onWrite = func([]byte) {
		if msgSeq.Add(1) == 2 {
			_, err := ca.Write([]byte{0x01, 0x02})
			assert.NoError(t, err)
		}
	}
	go func() {
		client, err := testClient(
			ctx,
			caWithInvalidRecord,
			caWithInvalidRecord.RemoteAddr(),
			[]dtls.ClientOption{dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
			true,
		)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(
		ctx,
		cb,
		cb.RemoteAddr(),
		[]dtls.ServerOption{dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
		true,
	)

	errClient := <-clientErr

	defer func() {
		if server != nil {
			assert.NoError(t, server.Close())
		}

		if errClient.c != nil {
			assert.NoError(t, errClient.c.Close())
		}
	}()

	assert.NoError(t, errServer)
	assert.NoError(t, errClient.err)
}

func TestPionV4PSKCallbackFail(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	serverAlertError := expectedTextError("alert: " + (&alert.Alert{
		Level:       alert.Fatal,
		Description: alert.InternalError,
	}).String())
	pskRejected := errPSKRejected

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, cb := packetPipe()
	go func() {
		opts := []dtls.ClientOption{
			dtls.WithPSK(func() ([]dtls.PSK, error) { return nil, pskRejected }, nil),
			dtls.WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8),
		}

		_, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false)
		clientErr <- err
	}()

	opts := []dtls.ServerOption{
		dtls.WithPSK(nil, func(identities [][]byte) (*dtls.PSK, error) { return nil, pskRejected }),
		dtls.WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8),
	}

	_, err := testServer(ctx, cb, cb.RemoteAddr(), opts, false)
	assertInteropError(t, err, serverAlertError, "TestPSK: Server should fail with alert error")
	assertInteropError(t, <-clientErr, pskRejected, "TestPSK: Client should fail with pskRejected error")
}

func TestPionV4SRTPConfiguration(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	tests := []srtpConfigurationTest{
		{
			Name: "No SRTP in use",
		},
		{
			Name:                          "SRTP with echoed MKI",
			ClientSRTP:                    []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:                    []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ClientSRTPMasterKeyIdentifier: []byte("ClientSRTPMKI"),
			ServerSRTPMasterKeyIdentifier: []byte("ClientSRTPMKI"),
			ExpectedClientMKI:             []byte("ClientSRTPMKI"),
			ExpectedServerMKI:             []byte("ClientSRTPMKI"),
			ExpectedProfile:               dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
		{
			Name:                          "SRTP with declined MKI",
			ClientSRTP:                    []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:                    []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ClientSRTPMasterKeyIdentifier: []byte("ClientSRTPMKI"),
			ServerSRTPMasterKeyIdentifier: []byte("OtherMKI"),
			ExpectedServerMKI:             []byte("ClientSRTPMKI"),
			ExpectedProfile:               dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
		{
			Name:            "SRTP client only",
			ClientSRTP:      []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			WantServerError: expectedTextError("client requested SRTP but we have no matching profiles"),
		},
		{
			Name:            "SRTP server only",
			ClientSRTP:      nil,
			ServerSRTP:      []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: 0,
			WantClientError: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			WantServerError: expectedTextError("client requested SRTP but we have no matching profiles"),
		},
		{
			Name: "Multiple Suites",
			ClientSRTP: []dtls.SRTPProtectionProfile{
				dtls.SRTP_AES128_CM_HMAC_SHA1_80,
				dtls.SRTP_AES128_CM_HMAC_SHA1_32,
			},
			ServerSRTP: []dtls.SRTPProtectionProfile{
				dtls.SRTP_AES128_CM_HMAC_SHA1_80,
				dtls.SRTP_AES128_CM_HMAC_SHA1_32,
			},
			ExpectedProfile: dtls.SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name: "Multiple Suites, Server Chooses",
			ClientSRTP: []dtls.SRTPProtectionProfile{
				dtls.SRTP_AES128_CM_HMAC_SHA1_80,
				dtls.SRTP_AES128_CM_HMAC_SHA1_32,
			},
			ServerSRTP: []dtls.SRTPProtectionProfile{
				dtls.SRTP_AES128_CM_HMAC_SHA1_32,
				dtls.SRTP_AES128_CM_HMAC_SHA1_80,
			},
			ExpectedProfile: dtls.SRTP_AES128_CM_HMAC_SHA1_32,
			WantClientError: nil,
			WantServerError: nil,
		},
	}
	for _, version := range []struct {
		name  string
		value protocol.Version
	}{
		{name: "DTLS12", value: protocol.Version1_2},
		{name: "DTLS13", value: protocol.Version1_3},
	} {
		for _, test := range tests {
			t.Run(version.name+"/"+test.Name, func(t *testing.T) {
				runSRTPConfiguration(t, version.value, test)
			})
		}
	}
}

func runSRTPConfiguration(t *testing.T, version protocol.Version, test srtpConfigurationTest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := packetPipe()
	type result struct {
		c   *dtls.Conn
		err error
	}
	resultCh := make(chan result)

	go func() {
		opts := []dtls.ClientOption{
			dtls.WithMinVersion(version),
			dtls.WithMaxVersion(version),
			dtls.WithSRTPMasterKeyIdentifier(test.ClientSRTPMasterKeyIdentifier),
		}
		if len(test.ClientSRTP) > 0 {
			opts = append(opts, dtls.WithSRTPProtectionProfiles(test.ClientSRTP...))
		}
		client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, true)
		resultCh <- result{client, err}
	}()

	opts := []dtls.ServerOption{
		dtls.WithMinVersion(version),
		dtls.WithMaxVersion(version),
		dtls.WithSRTPMasterKeyIdentifier(test.ServerSRTPMasterKeyIdentifier),
	}
	if len(test.ServerSRTP) > 0 {
		opts = append(opts, dtls.WithSRTPProtectionProfiles(test.ServerSRTP...))
	}
	server, err := testServer(ctx, cb, cb.RemoteAddr(), opts, true)
	assertInteropError(t, err, test.WantServerError)
	if server != nil {
		defer func() { _ = server.Close() }()
	}

	res := <-resultCh
	assertInteropError(t, res.err, test.WantClientError)
	if res.c != nil {
		defer func() { _ = res.c.Close() }()
	}
	if res.c == nil || server == nil {
		return
	}

	actualClientSRTP, _ := res.c.SelectedSRTPProtectionProfile()
	assert.Equal(t, test.ExpectedProfile, actualClientSRTP)
	actualServerSRTP, _ := server.SelectedSRTPProtectionProfile()
	assert.Equal(t, test.ExpectedProfile, actualServerSRTP)

	actualServerMKI, _ := server.RemoteSRTPMasterKeyIdentifier()
	assert.True(t, bytes.Equal(test.ExpectedServerMKI, actualServerMKI))
	if len(actualServerMKI) > 0 {
		actualServerMKI[0] ^= 0xff
		actualServerMKI, _ = server.RemoteSRTPMasterKeyIdentifier()
		assert.True(t, bytes.Equal(test.ExpectedServerMKI, actualServerMKI))
	}
	actualClientMKI, _ := res.c.RemoteSRTPMasterKeyIdentifier()
	assert.True(t, bytes.Equal(test.ExpectedClientMKI, actualClientMKI))
}

func TestPionV4ClientCertificate(t *testing.T) { //nolint:gocyclo,cyclop,maintidx
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	srvCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	srvCAPool := x509.NewCertPool()
	srvCertificate, err := x509.ParseCertificate(srvCert.Certificate[0])
	assert.NoError(t, err)

	srvCAPool.AddCert(srvCertificate)

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientOpts         []dtls.ClientOption
			serverOpts         []dtls.ServerOption
			clientAuth         dtls.ClientAuthType
			expectedClientCert [][]byte
			expectedServerCert [][]byte
			wantErr            bool
		}{
			"NoClientCert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.NoClientCert),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.NoClientCert,
				expectedServerCert: srvCert.Certificate,
			},
			"NoClientCert_ServerVerifyConnectionFails": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.NoClientCert),
					dtls.WithClientCAs(caPool),
					dtls.WithVerifyConnection(func(*dtls.State) error { return errExample }),
				},
				clientAuth:         dtls.NoClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"NoClientCert_ClientVerifyConnectionFails": {
				clientOpts: []dtls.ClientOption{
					dtls.WithRootCAs(srvCAPool),
					dtls.WithVerifyConnection(func(*dtls.State) error { return errExample }),
				},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.NoClientCert),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.NoClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"NoClientCert_cert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequireAnyClientCert),
				},
				clientAuth:         dtls.RequireAnyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_cert_sigscheme": { // specify signature algorithm
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithSignatureSchemes(tls.ECDSAWithP521AndSHA512),
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequestClientCert),
				},
				clientAuth:         dtls.RequestClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_cert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequestClientCert),
				},
				clientAuth:         dtls.RequestClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequestClientCert_no_cert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequestClientCert),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.RequestClientCert,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAnyClientCert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequireAnyClientCert),
				},
				clientAuth:         dtls.RequireAnyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAnyClientCert_error": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequireAnyClientCert),
				},
				clientAuth:         dtls.RequireAnyClientCert,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"VerifyClientCertIfGiven_no_cert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.VerifyClientCertIfGiven),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.VerifyClientCertIfGiven,
				expectedServerCert: srvCert.Certificate,
			},
			"VerifyClientCertIfGiven_cert": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.VerifyClientCertIfGiven),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.VerifyClientCertIfGiven,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"VerifyClientCertIfGiven_error": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(srvCAPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.VerifyClientCertIfGiven),
				},
				clientAuth:         dtls.VerifyClientCertIfGiven,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
				wantErr:            true,
			},
			"RequireAndVerifyClientCert": {
				clientOpts: []dtls.ClientOption{
					dtls.WithRootCAs(srvCAPool),
					dtls.WithCertificates(cert),
					dtls.WithVerifyConnection(func(s *dtls.State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], srvCertificate.Raw); !ok {
							return errExample
						}

						return nil
					}),
				},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(srvCert),
					dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
					dtls.WithClientCAs(caPool),
					dtls.WithVerifyConnection(func(s *dtls.State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], certificate.Raw); !ok {
							return errExample
						}

						return nil
					}),
				},
				clientAuth:         dtls.RequireAndVerifyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
			"RequireAndVerifyClientCert_callbacks": {
				clientOpts: []dtls.ClientOption{
					dtls.WithRootCAs(srvCAPool),
					dtls.WithGetClientCertificate(func(*dtls.CertificateRequestInfo) (
						*tls.Certificate,
						error,
					) {
						return &cert, nil
					}),
				},
				serverOpts: []dtls.ServerOption{
					dtls.WithGetCertificate(func(*dtls.ClientHelloInfo) (
						*tls.Certificate,
						error,
					) {
						return &srvCert, nil
					}),
					dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
					dtls.WithClientCAs(caPool),
				},
				clientAuth:         dtls.RequireAndVerifyClientCert,
				expectedClientCert: cert.Certificate,
				expectedServerCert: srvCert.Certificate,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				client, server := handshakePair(t, tt.clientOpts, tt.serverOpts)

				if tt.wantErr {
					assert.True(
						t,
						client.configErr != nil || client.handshakeError != nil ||
							server.configErr != nil || server.handshakeError != nil,
						"Error expected",
					)

					return // Error expected, test succeeded
				}
				assert.NoError(t, client.configErr)
				assert.NoError(t, client.handshakeError)
				assert.NoError(t, server.configErr)
				assert.NoError(t, server.handshakeError)

				state, ok := server.conn.ConnectionState()
				assert.True(t, ok, "Server connection state not available")

				actualClientCert := state.PeerCertificates
				if tt.expectedClientCert != nil {
					assert.NotNil(t, actualClientCert, "Client did not provide a certificate")
					assert.Equal(
						t,
						actualClientCert[0],
						tt.expectedClientCert[0],
						"Client certificate was not communicated correctly",
					)
				}
				if tt.clientAuth == dtls.NoClientCert {
					assert.Nil(t, actualClientCert, "Client certificate wasn't expected")
				}

				clientState, ok := client.conn.ConnectionState()
				assert.True(t, ok, "Client connection state not available")

				actualServerCert := clientState.PeerCertificates
				assert.NotNil(t, actualServerCert, "server did not provide a certificate")

				assert.NotEmpty(t, tt.expectedServerCert, "Server certificate was not communicated correctly")
				assert.Equal(
					t,
					actualServerCert[0],
					tt.expectedServerCert[0],
					"Server certificate was not communicated correctly",
				)
			})
		}
	})
}

func TestPionV4ExtendedMasterSecret(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	tests := map[string]struct {
		clientOpts        []dtls.ClientOption
		serverOpts        []dtls.ServerOption
		expectedClientErr error
		expectedServerErr error
	}{
		"Request_Request_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Require_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Disable_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Request_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Require_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Disable_ExtendedMasterSecret": {
			clientOpts: []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			serverOpts: []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			expectedClientErr: expectedTextError("client required Extended Master Secret extension, " +
				"but server does not support it"),
			expectedServerErr: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
		},
		"Disable_Request_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Disable_Require_ExtendedMasterSecret": {
			clientOpts: []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			serverOpts: []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret)},
			expectedClientErr: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			expectedServerErr: expectedTextError("server requires the Extended Master Secret extension, " +
				"but the client does not support it"),
		},
		"Disable_Disable_ExtendedMasterSecret": {
			clientOpts:        []dtls.ClientOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			serverOpts:        []dtls.ServerOption{dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret)},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *dtls.Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, ca, ca.RemoteAddr(), tt.clientOpts, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, cb, cb.RemoteAddr(), tt.serverOpts, true)
			res := <-c
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()
			assertInteropError(t, res.err, tt.expectedClientErr)
			assertInteropError(t, err, tt.expectedServerErr)
		})
	}
}

func TestPionV4ServerCertificate(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientOpts []dtls.ClientOption
			serverOpts []dtls.ServerOption
			wantErr    bool
		}{
			"no_ca": {
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
				wantErr:    true,
			},
			"good_ca": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(caPool)},
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
			},
			"no_ca_skip_verify": {
				clientOpts: []dtls.ClientOption{dtls.WithInsecureSkipVerify(true)},
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
			},
			"good_ca_skip_verify_custom_verify_peer": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(caPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithCertificates(cert),
					dtls.WithClientAuth(dtls.RequireAnyClientCert),
					dtls.WithVerifyPeerCertificate(func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) != 0 {
							return errNotExpectedChain
						}

						return nil
					}),
				},
			},
			"good_ca_verify_custom_verify_peer": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(caPool), dtls.WithCertificates(cert)},
				serverOpts: []dtls.ServerOption{
					dtls.WithClientCAs(caPool),
					dtls.WithCertificates(cert),
					dtls.WithClientAuth(dtls.RequireAndVerifyClientCert),
					dtls.WithVerifyPeerCertificate(func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) == 0 {
							return errExpectedChain
						}

						return nil
					}),
				},
			},
			"good_ca_custom_verify_peer": {
				clientOpts: []dtls.ClientOption{
					dtls.WithRootCAs(caPool),
					dtls.WithVerifyPeerCertificate(func([][]byte, [][]*x509.Certificate) error { return errWrongCert }),
				},
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
				wantErr:    true,
			},
			"server_name": {
				clientOpts: []dtls.ClientOption{
					dtls.WithRootCAs(caPool),
					dtls.WithServerName(certificate.Subject.CommonName),
				},
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
			},
			"server_name_error": {
				clientOpts: []dtls.ClientOption{dtls.WithRootCAs(caPool), dtls.WithServerName("barfoo")},
				serverOpts: []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithClientAuth(dtls.NoClientCert)},
				wantErr:    true,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				client, _ := handshakePair(t, tt.clientOpts, tt.serverOpts)
				if tt.wantErr {
					assert.True(t, client.configErr != nil || client.handshakeError != nil, "Expected error")
				} else {
					assert.NoError(t, client.configErr, "Client connection failed")
					assert.NoError(t, client.handshakeError, "Client handshake failed")
				}
			})
		}
	})
}

func TestPionV4CipherSuiteConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                    string
		ClientCipherSuites      []cryptosuite.ID
		ServerCipherSuites      []cryptosuite.ID
		WantClientError         error
		WantServerError         error
		WantSelectedCipherSuite cryptosuite.ID
	}{
		{
			Name:               "No cipherSuites specified",
			ClientCipherSuites: nil,
			ServerCipherSuites: nil,
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "Invalid CipherSuite",
			ClientCipherSuites: []cryptosuite.ID{0x00},
			ServerCipherSuites: []cryptosuite.ID{0x00},
			WantClientError:    expectedTextError("CipherSuite with id(0) is not valid"),
			WantServerError:    expectedTextError("CipherSuite with id(0) is not valid"),
		},
		{
			Name:                    "Valid cipherSuites specified",
			ClientCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:               "cipherSuites mismatch",
			ClientCipherSuites: []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			WantServerError: expectedTextError("client+server do not support any shared cipher suites"),
		},
		{
			Name:                    "Valid cipherSuites CCM specified",
			ClientCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			ServerCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		},
		{
			Name:                    "Valid cipherSuites CCM-8 specified",
			ClientCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			ServerCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		},
		{
			Name: "Server supports subset of client suites",
			ClientCipherSuites: []cryptosuite.ID{
				cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			},
			ServerCipherSuites:      []cryptosuite.ID{cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *dtls.Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				var opts []dtls.ClientOption
				if len(test.ClientCipherSuites) > 0 {
					opts = append(opts, dtls.WithCipherSuites(test.ClientCipherSuites...))
				}
				client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, true)
				resultCh <- result{client, err}
			}()

			var opts []dtls.ServerOption
			if len(test.ServerCipherSuites) > 0 {
				opts = append(opts, dtls.WithCipherSuites(test.ServerCipherSuites...))
			}
			server, err := testServer(ctx, cb, cb.RemoteAddr(), opts, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			}
			assertInteropError(
				t,
				err,
				test.WantServerError,
				"TestCipherSuiteConfiguration: Server Error Mismatch '%s'",
				test.Name,
			)

			res := <-resultCh
			if err == nil {
				assert.NoError(t, server.Close())
				assert.NoError(t, res.c.Close())
			}
			assertInteropError(
				t,
				res.err,
				test.WantClientError,
				"TestCipherSuiteConfiguration: Client Error Mismatch '%s'",
			)
			if test.WantSelectedCipherSuite != 0x00 {
				assert.Equal(
					t,
					test.WantSelectedCipherSuite,
					connectionState(t, res.c).CipherSuiteID,
					"TestCipherSuiteConfiguration: Server Selected Bad Cipher Suite '%s'",
					test.Name,
				)
			}
		})
	}
}

func TestPionV4CertificateAndPSKServer(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name              string
		ClientPSK         bool
		ClientAuth        dtls.ClientAuthType
		ClientCertificate bool
		WantServerError   error
	}{
		{
			Name:      "Client uses PKI",
			ClientPSK: false,
		},
		{
			Name:      "Client uses psk",
			ClientPSK: true,
		},
		{
			Name:       "PSK with required client certificate",
			ClientPSK:  true,
			ClientAuth: dtls.RequireAnyClientCert,
		},
		{
			Name:       "PSK with required verified client certificate",
			ClientPSK:  true,
			ClientAuth: dtls.RequireAndVerifyClientCert,
		},
		{
			Name:            "Certificate suite requires client certificate despite PSK callback",
			ClientAuth:      dtls.RequireAnyClientCert,
			WantServerError: expectedTextError("server required client verification, but got none"),
		},
		{
			Name:            "Certificate suite requires verified client certificate despite PSK callback",
			ClientAuth:      dtls.RequireAndVerifyClientCert,
			WantServerError: expectedTextError("server required client verification, but got none"),
		},
		{
			Name:              "Certificate suite accepts client certificate with PSK callback",
			ClientAuth:        dtls.RequireAnyClientCert,
			ClientCertificate: true,
		},
		{
			Name:       "Certificate suite permits empty certificate when optional",
			ClientAuth: dtls.RequestClientCert,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			type result struct {
				c   *dtls.Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				opts := []dtls.ClientOption{dtls.WithCipherSuites(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
				if test.ClientPSK {
					opts = []dtls.ClientOption{dtls.WithPSK(func() ([]dtls.PSK, error) {
						return []dtls.PSK{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
					}, nil), dtls.WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_GCM_SHA256)}
				}

				client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, test.ClientCertificate)
				resultCh <- result{client, err}
			}()

			opts := []dtls.ServerOption{
				dtls.WithCipherSuites(
					cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					cryptosuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
				),
				dtls.WithPSK(nil, func(identities [][]byte) (*dtls.PSK, error) {
					return &dtls.PSK{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
				}),
			}

			opts = append(opts, dtls.WithClientAuth(test.ClientAuth))
			server, err := testServer(ctx, cb, cb.RemoteAddr(), opts, true)
			assertInteropError(t, err, test.WantServerError)
			if server != nil {
				defer func() {
					assert.NoError(t, server.Close())
				}()
			}

			res := <-resultCh
			if res.c != nil {
				defer func() {
					assert.NoError(t, res.c.Close())
				}()
			}
			if test.WantServerError != nil {
				assert.Error(t, res.err)

				return
			}
			assert.NoErrorf(t, res.err, "TestCertificateAndPSKServer: Server Error Mismatch '%s'", test.Name)
		})
	}
}

func TestPionV4PSKConfiguration(t *testing.T) { //nolint:cyclop
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            dtls.PSKClientCallback
		ServerPSK            dtls.PSKServerCallback
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "psk and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK: func() ([]dtls.PSK, error) {
				return []dtls.PSK{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
			},
			ServerPSK: func(identities [][]byte) (*dtls.PSK, error) {
				return &dtls.PSK{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
			},
			WantClientError: expectedTextError("connection can not be created, pre-shared key present " +
				"but no compatible CipherSuite"),
			WantServerError: expectedTextError("connection can not be created, pre-shared key present " +
				"but no compatible CipherSuite"),
		},
		{
			Name:                 "psk and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK: func() ([]dtls.PSK, error) {
				return []dtls.PSK{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
			},
			ServerPSK: func(identities [][]byte) (*dtls.PSK, error) {
				return &dtls.PSK{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
			},
			WantClientError: expectedTextError("connection can not be created, pre-shared key present " +
				"but no compatible CipherSuite"),
			WantServerError: expectedTextError("connection can not be created, pre-shared key present " +
				"but no compatible CipherSuite"),
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := packetPipe()
		type result struct {
			c   *dtls.Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			var opts []dtls.ClientOption
			if test.ClientPSK != nil {
				opts = append(opts, dtls.WithPSK(test.ClientPSK, nil))
			}
			client, err := testClient(
				ctx,
				ca,
				ca.RemoteAddr(),
				opts,
				test.ClientHasCertificate,
			)
			resultCh <- result{client, err}
		}()

		var opts []dtls.ServerOption
		if test.ServerPSK != nil {
			opts = append(opts, dtls.WithPSK(nil, test.ServerPSK))
		}
		_, err := testServer(
			ctx,
			cb,
			cb.RemoteAddr(),
			opts,
			test.ServerHasCertificate,
		)
		if err != nil || test.WantServerError != nil {
			if err == nil || test.WantServerError == nil || err.Error() != test.WantServerError.Error() {
				assert.Failf(t, "TestPSKConfiguration", "Server Error Mismatch '%s'", test.Name)
			}
		}

		res := <-resultCh
		if res.err != nil || test.WantClientError != nil {
			if res.err == nil || test.WantClientError == nil && res.err.Error() != test.WantClientError.Error() {
				assert.Failf(t, "TestPSKConfiguration", "Client Error Mismatch '%s'", test.Name)
			}
		}
	}
}

func TestPionV4MultipleHelloVerifyRequest(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookies := [][]byte{
		// first clientHello contains an empty cookie
		{},
	}
	var packets [][]byte
	for i := range 2 {
		cookie := make([]byte, 20)
		_, err := rand.Read(cookie)
		assert.NoError(t, err)

		cookies = append(cookies, cookie)

		record := &testRecord{
			Header: recordlayer.RecordConfig{SequenceNumber: uint64(i), Version: protocol.Version1_2},
			Content: &handshake.Handshake{
				Header:  handshake.Header{MessageSequence: uint16(i)},
				Message: &handshake.MessageHelloVerifyRequest{Version: protocol.Version1_2, Cookie: cookie},
			},
		}
		packet, err := record.Marshal()
		assert.NoError(t, err)

		packets = append(packets, packet)
	}

	ca, cb := packetPipe()
	defer func() {
		assert.NoError(t, ca.Close())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	assert.NoError(t, cb.SetReadDeadline(deadline))

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		_, _ = testClient(ctx, ca, ca.RemoteAddr(), []dtls.ClientOption{
			dtls.WithFlightInterval(100 * time.Millisecond),
		}, false)
	}()

	for i, cookie := range cookies {
		// read client hello
		resp := make([]byte, 1024)
		n, err := cb.Read(resp)
		if !assert.NoError(t, err) {
			return
		}

		_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])
		clientHello, ok := handshakeRecord.Message.(*handshake.MessageClientHello)
		assert.True(t, ok)
		assert.Equal(t, cookie, clientHello.Cookie)
		if len(packets) <= i {
			break
		}
		// write hello verify request
		_, err = cb.Write(packets[i])
		assert.NoError(t, err)
	}
	cancel()
}

func TestPionV4ServerNameIndicationExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name       string
		serverName string
		Expected   []byte
		IncludeSNI bool
	}{
		{
			Name:       "Server name is a valid hostname",
			serverName: "example.com",
			Expected:   []byte("example.com"),
			IncludeSNI: true,
		},
		{
			Name:       "Server name is an IP literal",
			serverName: "1.2.3.4",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
		{
			Name:       "Server name is empty",
			serverName: "",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := packetPipe()
			go func() {
				_, _ = testClient(
					ctx,
					ca,
					ca.RemoteAddr(),
					[]dtls.ClientOption{dtls.WithServerName(test.serverName)},
					false,
				)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			assert.NoError(t, err)

			_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])

			clientHello, ok := handshakeRecord.Message.(*handshake.MessageClientHello)
			assert.True(t, ok)

			gotSNI := false
			var actualServerName string
			for _, v := range clientHello.Extensions {
				if _, ok := v.(*extension.ServerNameOffer); ok {
					gotSNI = true
					extensionServerName, ok := v.(*extension.ServerNameOffer)
					assert.True(t, ok)

					actualServerName = extensionServerName.ServerName
				}
			}

			assert.Equalf(t, test.IncludeSNI, gotSNI, "TestSNI: expected SNI inclusion '%s'", test.Name)
			assert.Equalf(t, test.Expected, []byte(actualServerName), "TestSNI: server name mismatch '%s'", test.Name)
		})
	}
}

func TestPionV4CipherSuiteMatchesCertificateType(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name           string
		cipherList     []cryptosuite.ID
		expectedCipher cryptosuite.ID
		generateRSA    bool
	}{
		{
			Name: "ECDSA Certificate with RSA CipherSuite first",
			cipherList: []cryptosuite.ID{
				cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			expectedCipher: cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name: "RSA Certificate with ECDSA CipherSuite first",
			cipherList: []cryptosuite.ID{
				cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			expectedCipher: cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			generateRSA:    true,
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			clientErr := make(chan error, 1)
			client := make(chan *dtls.Conn, 1)

			ca, cb := packetPipe()
			go func() {
				c, err := testClient(
					t.Context(),
					ca,
					ca.RemoteAddr(),
					[]dtls.ClientOption{dtls.WithCipherSuites(test.cipherList...)},
					false,
				)
				clientErr <- err
				client <- c
			}()

			var (
				signer crypto.Signer
				err    error
			)

			if test.generateRSA {
				signer, err = rsa.GenerateKey(rand.Reader, 2048)
				assert.NoError(t, err)
			} else {
				signer, err = ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader)
				assert.NoError(t, err)
			}

			serverCert, err := selfsign.SelfSign(signer)
			assert.NoError(t, err)

			s, err := testServer(
				t.Context(),
				cb,
				cb.RemoteAddr(),
				[]dtls.ServerOption{dtls.WithCipherSuites(test.cipherList...), dtls.WithCertificates(serverCert)},
				false,
			)
			assert.NoError(t, err)

			c := <-client
			assert.NoError(t, <-clientErr)
			assert.NoError(t, s.Close())
			assert.NoError(t, c.Close())

			state, ok := c.ConnectionState()
			assert.True(t, ok)
			assert.Equal(t, test.expectedCipher, state.CipherSuiteID)
		})
	}
}

func TestPionV4MultipleServerCertificates(t *testing.T) {
	fooCert, err := selfsign.GenerateSelfSignedWithDNS("foo")
	assert.NoError(t, err)

	barCert, err := selfsign.GenerateSelfSignedWithDNS("bar")
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	for _, cert := range []tls.Certificate{fooCert, barCert} {
		certificate, err := x509.ParseCertificate(cert.Certificate[0])
		assert.NoError(t, err)
		caPool.AddCert(certificate)
	}

	for _, test := range []struct {
		RequestServerName string
		ExpectedDNSName   string
	}{
		{
			"foo",
			"foo",
		},
		{
			"bar",
			"bar",
		},
		{
			"invalid",
			"foo",
		},
	} {
		t.Run(test.RequestServerName, func(t *testing.T) {
			clientErr := make(chan error, 2)
			client := make(chan *dtls.Conn, 1)

			ca, cb := packetPipe()
			go func() {
				clientConn, err := testClient(t.Context(), ca, ca.RemoteAddr(), []dtls.ClientOption{
					dtls.WithRootCAs(caPool),
					dtls.WithServerName(test.RequestServerName),
					dtls.WithVerifyPeerCertificate(func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
						certificate, err := x509.ParseCertificate(rawCerts[0])
						if err != nil {
							return err
						}

						if certificate.DNSNames[0] != test.ExpectedDNSName {
							return errWrongCert
						}

						return nil
					}),
				}, false)
				clientErr <- err
				client <- clientConn
			}()

			s, err := testServer(
				t.Context(),
				cb,
				cb.RemoteAddr(),
				[]dtls.ServerOption{dtls.WithCertificates(fooCert, barCert)},
				false,
			)
			assert.NoError(t, err)
			assert.NoError(t, <-clientErr)
			assert.NoError(t, s.Close())
			assert.NoError(t, (<-client).Close())
		})
	}
}

func TestPionV4SkipHelloVerify(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := packetPipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(
			ctx,
			cb,
			cb.RemoteAddr(),
			[]dtls.ServerOption{
				dtls.WithCertificates(certificate),
				dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
				dtls.WithInsecureSkipVerifyHello(true),
			},
			false,
		)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)
		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(
		ctx,
		ca,
		ca.RemoteAddr(),
		[]dtls.ClientOption{
			dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
			dtls.WithInsecureSkipVerify(true),
		},
		false,
	)
	assert.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)

	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

func TestPionV4HelloRandom(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := packetPipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	chRandom := [handshake.RandomBytesLength]byte{}
	_, err = rand.Read(chRandom[:])
	assert.NoError(t, err)

	go func() {
		server, sErr := testServer(ctx, cb, cb.RemoteAddr(), []dtls.ServerOption{
			dtls.WithGetCertificate(func(chi *dtls.ClientHelloInfo) (*tls.Certificate, error) {
				if len(chi.CipherSuites) == 0 {
					return &certificate, nil
				}
				assert.Equal(t, chRandom[:], chi.RandomBytes[:])

				return &certificate, nil
			}),
			dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		}, false)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(
		ctx,
		ca,
		ca.RemoteAddr(),
		[]dtls.ClientOption{
			dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
			dtls.WithHelloRandomBytesGenerator(func() [handshake.RandomBytesLength]byte { return chRandom }),
			dtls.WithInsecureSkipVerify(true),
		},
		false,
	)
	assert.NoError(t, err)

	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)

	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}

	assert.NoError(t, client.Close())
}

func TestPionV4OnConnectionAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*20)
	defer cancel()

	var clientOnConnectionAttempt, serverOnConnectionAttempt atomic.Int32

	ca, cb := packetPipe()
	clientErr := make(chan error, 1)
	go func() {
		_, err := testClient(ctx, ca, ca.RemoteAddr(), nil, true)
		clientErr <- err
	}()

	expectedErr := errConnectionAttemptFailed
	_, err := testServer(ctx, cb, cb.RemoteAddr(), []dtls.ServerOption{
		dtls.WithOnConnectionAttempt(func(in net.Addr) error {
			serverOnConnectionAttempt.Store(1)
			assert.NotNil(t, in)

			return expectedErr
		}),
	}, true)
	assertInteropError(t, err, expectedErr)
	assert.Error(t, <-clientErr)
	assert.Equal(t, int32(1), serverOnConnectionAttempt.Load(), "onConnectionAttempt did not fire for server")
	assert.Equal(t, int32(0), clientOnConnectionAttempt.Load(), "onConnectionAttempt fired for client")
}

func TestPionV4ConnectionState(t *testing.T) {
	ca, cb := packetPipe()

	// Setup client
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := dtls.Client(
		ca,
		ca.RemoteAddr(),
		dtls.WithCertificates(clientCert),
		dtls.WithInsecureSkipVerify(true),
	)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorChannel := make(chan error)
	go func() {
		errC := client.HandshakeContext(ctx)
		errorChannel <- errC
	}()

	// Setup server
	server, err := testServer(ctx, cb, cb.RemoteAddr(), nil, true)
	assert.NoError(t, err)

	defer func() {
		_ = server.Close()
	}()

	err = <-errorChannel
	assert.NoError(t, err)

	_, ok = client.ConnectionState()
	assert.True(t, ok)
}

func TestPionV4MultiHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	ca, cb := packetPipe()
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	server, err := dtls.Server(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
	assert.NoError(t, err)

	go func() {
		_ = server.Handshake()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := dtls.Client(ca, ca.RemoteAddr(), dtls.WithCertificates(clientCert))
	assert.NoError(t, err)
	assert.Error(t, client.Handshake())
	assert.Error(t, client.Handshake())
	assert.NoError(t, server.Close())
	assert.NoError(t, client.Close())
}

func TestPionV4CloseDuringHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	for range 100 {
		_, cb := packetPipe()
		server, err := dtls.Server(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
		assert.NoError(t, err)

		waitChan := make(chan struct{})
		go func() {
			close(waitChan)
			_ = server.Handshake()
		}()

		<-waitChan
		assert.NoError(t, server.Close())
	}
}

func TestPionV4CloseWithoutHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	_, cb := packetPipe()
	server, err := dtls.Server(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
}

func TestPionV4DTLS13RetransmittedClientFinalFlight(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(10 * time.Second).Stop()

	ca, cb := packetPipe()
	var duplicated atomic.Bool
	duplicateWriteErr := make(chan error, 1)
	caDuplicateFinal := &connWithCallback{
		packetTestConn: ca,
		onWrite: func(raw []byte) {
			if len(raw) == 0 || !protocol.IsDTLS13Ciphertext(protocol.ContentType(raw[0])) || !duplicated.CompareAndSwap(
				false,
				true,
			) {
				return
			}
			if _, err := ca.Write(append([]byte(nil), raw...)); err != nil {
				duplicateWriteErr <- err
			}
		},
	}

	clientCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, err := dtls.Client(
		caDuplicateFinal,
		caDuplicateFinal.RemoteAddr(),
		dtls.WithCertificates(clientCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	server, err := dtls.Server(
		cb,
		cb.RemoteAddr(),
		dtls.WithCertificates(serverCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
	)
	require.NoError(t, err)
	defer func() {
		_ = server.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorChannel := make(chan error, 2)
	go func() {
		errorChannel <- client.HandshakeContext(ctx)
	}()
	go func() {
		errorChannel <- server.HandshakeContext(ctx)
	}()
	require.NoError(t, <-errorChannel)
	require.NoError(t, <-errorChannel)
	require.True(t, duplicated.Load())
	select {
	case err = <-duplicateWriteErr:
		require.NoError(t, err)
	default:
	}

	payload := []byte("application data after retransmit")
	_, err = client.Write(payload)
	require.NoError(t, err)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, len(payload))
	n, err := io.ReadFull(server, buf)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.Equal(t, payload, buf)
}

func testDTLSDualStackVersions(t *testing.T, clientMax, serverMax protocol.Version) {
	t.Helper()
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()
	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	clientOpts := []dtls.ClientOption{
		dtls.WithCertificates(clientCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(clientMax),
	}
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	serverOpts := []dtls.ServerOption{
		dtls.WithCertificates(serverCert),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(serverMax),
	}
	testDTLSDualStack(t, clientOpts, serverOpts)
}

func TestPionV4DTLSDualStackClient(t *testing.T) {
	testDTLSDualStackVersions(t, protocol.Version1_3, protocol.Version1_2)
}

func TestPionV4DTLSDualStackClientRejectsNonClientHelloBeforeWrite(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 5).Stop()

	ca, cb := packetPipe()
	defer func() {
		_ = ca.Close()
		_ = cb.Close()
	}()

	var writes atomic.Int32
	caCount := &connWithCallback{
		packetTestConn: ca,
		onWrite: func([]byte) {
			writes.Add(1)
		},
	}

	cipherSuiteID := uint16(cryptosuite.TLS_AES_128_GCM_SHA256)
	client, err := dtls.Client(
		caCount,
		caCount.RemoteAddr(),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithClientHelloMessageHook(func(handshake.MessageClientHello) handshake.Message {
			return &handshake.MessageServerHello{
				Version:           protocol.Version1_2,
				CipherSuiteID:     &cipherSuiteID,
				CompressionMethod: protocol.CompressionMethods()[0],
			}
		}),
	)
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = client.HandshakeContext(ctx)
	assertInteropError(t, err, expectedTextError("invalid ClientHello"))
	assert.Equal(t, int32(0), writes.Load())
}

func TestPionV4DTLSDualStackServer(t *testing.T) {
	testDTLSDualStackVersions(t, protocol.Version1_2, protocol.Version1_3)
}

func testDTLSDualStack(t *testing.T, clientOpts []dtls.ClientOption, serverOpts []dtls.ServerOption) {
	t.Helper()
	ca, cb := packetPipe()

	client, err := dtls.Client(ca, ca.RemoteAddr(), clientOpts...)
	assert.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	assert.False(t, ok)

	ctxClient, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelClient()
	errorChannel := make(chan error, 2)

	server, err := dtls.Server(cb, cb.RemoteAddr(), serverOpts...)
	assert.NoError(t, err)
	defer func() {
		_ = server.Close()
	}()

	_, ok = server.ConnectionState()
	assert.False(t, ok)

	ctxServer, cancelServer := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelServer()

	go func() {
		errC := client.HandshakeContext(ctxClient)
		errorChannel <- errC
	}()

	go func() {
		errS := server.HandshakeContext(ctxServer)
		errorChannel <- errS
	}()

	err = <-errorChannel
	assert.NoError(t, err)

	err = <-errorChannel
	assert.NoError(t, err)

	assert.NoError(t, server.Close())
	assert.NoError(t, client.Close())
}

func TestPionV4DetachedConnEvents(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4444}
	serverAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555}
	for _, testCase := range []struct {
		name string
		min  protocol.Version
		max  protocol.Version
	}{
		{name: "DTLS12", min: protocol.Version1_2, max: protocol.Version1_2},
		{name: "DTLS13", min: protocol.Version1_3, max: protocol.Version1_3},
		{name: "DualStack", min: protocol.Version1_2, max: protocol.Version1_3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client, err := dtls.DetachedClient(serverAddr,
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMinVersion(testCase.min),
				dtls.WithMaxVersion(testCase.max),
				dtls.WithMTU(200),
			)
			require.NoError(t, err)
			server, err := dtls.DetachedServer(clientAddr,
				dtls.WithCertificates(certificate),
				dtls.WithMinVersion(testCase.min),
				dtls.WithMaxVersion(testCase.max),
				dtls.WithMTU(200),
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			require.NoError(t, client.Start(t.Context()))
			require.NoError(t, server.Start(t.Context()))

			clientDone, serverDone := false, false
			largestBatch := 0
			for range 64 {
				drainDetachedEvents(t, client, server, clientAddr, serverAddr, &clientDone, nil, &largestBatch)
				drainDetachedEvents(t, server, client, serverAddr, clientAddr, &serverDone, nil, &largestBatch)
				if clientDone && serverDone {
					break
				}
			}
			require.True(t, clientDone)
			require.True(t, serverDone)
			require.Greater(t, largestBatch, 1)

			for _, payload := range [][]byte{[]byte("first application record"), []byte("second application record")} {
				n, writeErr := client.Write(payload)
				require.NoError(t, writeErr)
				require.Equal(t, len(payload), n)
				var received []byte
				drainDetachedEvents(t, client, server, clientAddr, serverAddr, nil, nil, nil)
				drainDetachedEvents(t, server, client, serverAddr, clientAddr, nil, &received, nil)
				require.Equal(t, payload, received)
			}
		})
	}
}

func TestPionV4DetachedConnLifecycle(t *testing.T) {
	serverAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555}
	client, err := dtls.DetachedClient(serverAddr, dtls.WithInsecureSkipVerify(true))
	require.NoError(t, err)
	startedClient := client
	t.Cleanup(func() { _ = startedClient.Close() })
	requireInteropError(t, client.HandleDatagram([]byte{0}, serverAddr), expectedTextError("handshake is in progress"))
	_, err = client.Write([]byte("early"))
	requireInteropError(t, err, expectedTextError("handshake is in progress"))
	require.NoError(t, client.Start(t.Context()))
	requireInteropError(t, client.Start(t.Context()), expectedTextError("DetachedConn.Start called more than once"))

	client, err = dtls.DetachedClient(nil)
	requireInteropError(t, err, expectedTextError("remote address cannot be nil"))
	require.Nil(t, client)
}

func TestPionV4DetachedConnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	client, err := dtls.DetachedClient(
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555},
		dtls.WithInsecureSkipVerify(true),
	)
	require.NoError(t, err)
	require.NoError(t, client.Start(ctx))
	for event := client.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = client.NextEvent() {
	}
	cancel()
	requireDetachedEventReady(t, client)

	var closedErr error
	for event := client.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = client.NextEvent() {
		if event.Kind == dtls.DetachedClosed {
			closedErr = event.Err
		}
	}
	requireInteropError(t, closedErr, context.Canceled)
}

func TestPionV4DetachedConnAutonomousRetransmit(t *testing.T) {
	for name, versions := range map[string][2]protocol.Version{
		"DTLS12":    {protocol.Version1_2, protocol.Version1_2},
		"DTLS13":    {protocol.Version1_3, protocol.Version1_3},
		"DualStack": {protocol.Version1_2, protocol.Version1_3},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := dtls.DetachedClient(
				&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5555},
				dtls.WithInsecureSkipVerify(true),
				dtls.WithMinVersion(versions[0]),
				dtls.WithMaxVersion(versions[1]),
				dtls.WithFlightInterval(100*time.Millisecond),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			require.NoError(t, client.Start(t.Context()))

			initialWrites := 0
			for event := client.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = client.NextEvent() {
				if event.Kind == dtls.DetachedWriteDatagrams {
					require.NotEmpty(t, event.Datagrams)
					initialWrites++
				}
			}
			require.Equal(t, 1, initialWrites)
			select {
			case <-client.EventReady():
				require.Fail(t, "stale readiness signal before retransmission")
			default:
			}

			requireDetachedEventReady(t, client)

			retransmitWrites := 0
			for event := client.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = client.NextEvent() {
				if event.Kind == dtls.DetachedWriteDatagrams {
					require.NotEmpty(t, event.Datagrams)
					retransmitWrites++
				}
			}
			require.Equal(t, 1, retransmitWrites)
			select {
			case <-client.EventReady():
				require.Fail(t, "stale readiness signal after retransmission")
			default:
			}
		})
	}
}

func TestPionV4ServerRetainsRejectedTransport(t *testing.T) {
	ca, cb := packetPipe()
	defer func() { _ = ca.Close() }()
	defer func() { _ = cb.Close() }()
	expected := errConnectionAttemptFailed
	_, err := dtls.Server(cb, cb.RemoteAddr(), dtls.WithOnConnectionAttempt(func(net.Addr) error { return expected }))
	require.ErrorIs(t, err, expected)
	require.NoError(t, cb.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err = cb.Write([]byte("still open"))
	require.NoError(t, err)
	require.NoError(t, ca.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 16)
	n, err := ca.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, "still open", string(buffer[:n]))
}

func TestPionV4SimpleReadWrite(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := packetPipe()
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(
			ctx,
			cb,
			cb.RemoteAddr(),
			[]dtls.ServerOption{
				dtls.WithCertificates(certificate),
				dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
			},
			false,
		)
		assert.NoError(t, sErr)

		buf := make([]byte, 1024)
		_, sErr = server.Read(buf) //nolint:contextcheck
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close()) //nolint:contextcheck
	}()

	client, err := testClient(
		ctx,
		ca,
		ca.RemoteAddr(),
		[]dtls.ClientOption{
			dtls.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
			dtls.WithInsecureSkipVerify(true),
		},
		false,
	)
	assert.NoError(t, err)
	_, err = client.Write([]byte("hello"))
	assert.NoError(t, err)
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

func TestPionV4ReceiveBufferSizeLargeDatagram(t *testing.T) {
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Larger than the 8192-byte default receive buffer, small enough that the
	// resulting datagram fits well under platform datagram limits (macOS caps
	// UDP datagrams at net.inet.udp.maxdgram, 9216 bytes by default).
	const payloadSize = 8500
	const bufferSize = 16384

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	packetConn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	)
	require.NoError(t, err)

	listener, err := dtls.Listen(
		packetConn,
		dtls.WithCertificates(serverCert),
		dtls.WithReceiveBufferSize(bufferSize),
	)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, listener.Close())
	}()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	type readResult struct {
		data []byte
		err  error
	}
	serverRead := make(chan readResult, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverRead <- readResult{err: acceptErr}

			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, bufferSize)
		n, readErr := conn.Read(buf)
		serverRead <- readResult{data: buf[:n], err: readErr}

		assert.NoError(t, conn.Close())
	}()

	serverAddr, ok := listener.Addr().(*net.UDPAddr)
	require.True(t, ok)

	client, err := dtls.Dial("udp", serverAddr,
		dtls.WithInsecureSkipVerify(true),
		dtls.WithReceiveBufferSize(bufferSize),
	)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, client.Close())
	}()

	n, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, payloadSize, n)

	res := <-serverRead
	require.NoError(t, res.err)
	assert.Equal(t, payload, res.data)
}

func TestPionV4ReplayProtection(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
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
		// Man in the middle
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
				// Replay bit later
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
		atomic.AddInt32(&cntReplays, 1) // Keep locked until the final message
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
					// Final message received
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
	time.Sleep(10 * time.Millisecond) // Ensure all replayed packets are sent

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
