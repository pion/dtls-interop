// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

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

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPionV3StressDuplex(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

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

func TestPionV3RoutineLeakOnClose(t *testing.T) {
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	ca, cb, err := pipeMemory()
	assert.NoError(t, err)

	_, err = ca.Write(make([]byte, 100))
	assert.NoError(t, err)
	assert.NoError(t, cb.Close())
	assert.NoError(t, ca.Close())

}

func TestPionV3ReadWriteDeadline(t *testing.T) {
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

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
	assert.True(t, netErr.Temporary(), "Deadline exceeded Write must return Temporary")

	_, rerr := ca.Read(make([]byte, 100))
	assert.ErrorAs(t, rerr, &netErr, "Read must return net.Error")
	assert.True(t, netErr.Timeout(), "Deadline exceeded Read must return Timeout")
	assert.True(t, netErr.Temporary(), "Deadline exceeded Read must return Temporary")
	assert.NoError(t, ca.SetDeadline(time.Time{}))
	assert.NoError(t, ca.Close())
	assert.NoError(t, cb.Close())

	_, err = ca.Write(make([]byte, 100))
	assertInteropError(t, err, dtls.ErrConnClosed)
	_, err = ca.Read(make([]byte, 100))
	assertInteropError(t, err, io.EOF)
}

func TestPionV3WriteReturnsZeroOnTransportError(t *testing.T) {
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

func TestPionV3HandshakeWithAlert(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

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
				dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			},
			clientOpts: []dtls.ClientOption{
				dtls.WithCipherSuites(dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
			},
			errServer: expectedTextError("client+server do not support any shared cipher suites"),
			errClient: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
		},
		"SignatureSchemesNoIntersection": {
			serverOpts: []dtls.ServerOption{
				dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
				dtls.WithSignatureSchemes(tls.ECDSAWithP256AndSHA256),
			},
			clientOpts: []dtls.ClientOption{
				dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
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

func TestPionV3HandshakeWithInvalidRecord(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

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
			[]dtls.ClientOption{dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
			true,
		)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(
		ctx,
		cb,
		cb.RemoteAddr(),
		[]dtls.ServerOption{dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
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

func TestPionV3PSKCallbackFail(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	serverAlertError := expectedTextError("alert: " + (&alert.Alert{
		Level:       alert.Fatal,
		Description: alert.InternalError,
	}).String())
	pskRejected := errPSKRejected

	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, cb := packetPipe()
	go func() {
		opts := []dtls.ClientOption{
			dtls.WithPSKIdentityHint([]byte{0}),
			withPSK(func() ([]psk, error) { return nil, pskRejected }, nil),
			dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8),
		}

		_, err := testClient(ctx, ca, ca.RemoteAddr(), opts, false)
		clientErr <- err
	}()

	opts := []dtls.ServerOption{
		withPSK(nil, func(identities [][]byte) (*psk, error) { return nil, pskRejected }),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8),
	}

	_, err := testServer(ctx, cb, cb.RemoteAddr(), opts, false)
	assertInteropError(t, err, serverAlertError, "TestPSK: Server should fail with alert error")
	assertInteropError(t, <-clientErr, pskRejected, "TestPSK: Client should fail with pskRejected error")
}

func TestPionV3SRTPConfiguration(t *testing.T) {
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
	if version != protocol.Version1_2 {
		t.Skip("Pion v3 supports DTLS 1.2 only")
	}
	if len(test.ClientSRTP) == 0 && len(test.ServerSRTP) > 0 {
		t.Skip("Server-only SRTP rejection is only fixed in v4 because it's a behavior change")
	}
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
			dtls.WithSRTPMasterKeyIdentifier(test.ClientSRTPMasterKeyIdentifier),
		}
		if len(test.ClientSRTP) > 0 {
			opts = append(opts, dtls.WithSRTPProtectionProfiles(test.ClientSRTP...))
		}
		client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, true)
		resultCh <- result{client, err}
	}()

	opts := []dtls.ServerOption{
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

func TestPionV3ClientCertificate(t *testing.T) {
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

	t.Run("parallel", func(t *testing.T) {
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
			"RequestClientCert_cert_sigscheme": {
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

					return
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

func TestPionV3ExtendedMasterSecret(t *testing.T) {
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

func TestPionV3ServerCertificate(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) {
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

func TestPionV3CipherSuiteConfiguration(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                    string
		ClientCipherSuites      []dtls.CipherSuiteID
		ServerCipherSuites      []dtls.CipherSuiteID
		WantClientError         error
		WantServerError         error
		WantSelectedCipherSuite dtls.CipherSuiteID
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
			ClientCipherSuites: []dtls.CipherSuiteID{0x00},
			ServerCipherSuites: []dtls.CipherSuiteID{0x00},
			WantClientError:    expectedTextError("CipherSuite with id(0) is not valid"),
			WantServerError:    expectedTextError("CipherSuite with id(0) is not valid"),
		},
		{
			Name:                    "Valid cipherSuites specified",
			ClientCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name:               "cipherSuites mismatch",
			ClientCipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError: expectedTextError("alert: " + (&alert.Alert{
				Level:       alert.Fatal,
				Description: alert.InsufficientSecurity,
			}).String()),
			WantServerError: expectedTextError("client+server do not support any shared cipher suites"),
		},
		{
			Name:                    "Valid cipherSuites CCM specified",
			ClientCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			ServerCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		},
		{
			Name:                    "Valid cipherSuites CCM-8 specified",
			ClientCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			ServerCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		},
		{
			Name: "Server supports subset of client suites",
			ClientCipherSuites: []dtls.CipherSuiteID{
				dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			},
			ServerCipherSuites:      []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
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

func TestPionV3CertificateAndPSKServer(t *testing.T) {
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
				opts := []dtls.ClientOption{dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
				if test.ClientPSK {
					opts = []dtls.ClientOption{dtls.WithPSKIdentityHint([]byte{0}), withPSK(func() ([]psk, error) {
						return []psk{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
					}, nil), dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256)}
				}

				client, err := testClient(ctx, ca, ca.RemoteAddr(), opts, test.ClientCertificate)
				resultCh <- result{client, err}
			}()

			opts := []dtls.ServerOption{
				dtls.WithCipherSuites(
					dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
				),
				withPSK(nil, func(identities [][]byte) (*psk, error) {
					return &psk{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
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

func TestPionV3PSKConfiguration(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            pskClientCallback
		ServerPSK            pskServerCallback
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "psk and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK: func() ([]psk, error) {
				return []psk{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
			},
			ServerPSK: func(identities [][]byte) (*psk, error) {
				return &psk{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
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
			ClientPSK: func() ([]psk, error) {
				return []psk{{Identity: []byte{0x00}, Key: []byte{0x00, 0x01, 0x02}}}, nil
			},
			ServerPSK: func(identities [][]byte) (*psk, error) {
				return &psk{Identity: identities[0], Key: []byte{0x00, 0x01, 0x02}}, nil
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
				opts = append(opts, dtls.WithPSKIdentityHint([]byte{0}), withPSK(test.ClientPSK, nil))
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
			opts = append(opts, withPSK(nil, test.ServerPSK))
		}
		_, err := testServer(
			ctx,
			cb,
			cb.RemoteAddr(),
			opts,
			test.ServerHasCertificate,
		)
		assertInteropError(t, err, test.WantServerError, test.Name)

		res := <-resultCh
		assertInteropError(t, res.err, test.WantClientError, test.Name)
	}
}

func TestPionV3MultipleHelloVerifyRequest(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	cookies := [][]byte{
		{},
	}
	var packets [][]byte
	for i := range 2 {
		cookie := make([]byte, 20)
		_, err := rand.Read(cookie)
		assert.NoError(t, err)

		cookies = append(cookies, cookie)

		record := &testRecord{
			Header: recordlayer.Header{SequenceNumber: uint64(i), Version: protocol.Version1_2},
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		_, _ = testClient(ctx, ca, ca.RemoteAddr(), nil, false)
	}()

	for i, cookie := range cookies {
		resp := make([]byte, 1024)
		n, err := cb.Read(resp)
		assert.NoError(t, err)

		_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])
		clientHello, ok := handshakeRecord.Message.(*handshake.MessageClientHello)
		assert.True(t, ok)
		assert.Equal(t, cookie, clientHello.Cookie)
		if len(packets) <= i {
			break
		}

		_, err = cb.Write(packets[i])
		assert.NoError(t, err)
	}
	cancel()
}

func TestPionV3ServerNameIndicationExtension(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

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

			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			assert.NoError(t, err)

			_, handshakeRecord := unmarshalHandshakeRecord(t, resp[:n])

			clientHello, ok := handshakeRecord.Message.(*handshake.MessageClientHello)
			assert.True(t, ok)

			gotSNI := false
			var actualServerName string
			for _, v := range clientHello.Extensions {
				if _, ok := v.(*extension.ServerName); ok {
					gotSNI = true
					extensionServerName, ok := v.(*extension.ServerName)
					assert.True(t, ok)

					actualServerName = extensionServerName.ServerName
				}
			}

			assert.Equalf(t, test.IncludeSNI, gotSNI, "TestSNI: expected SNI inclusion '%s'", test.Name)
			assert.Equalf(t, test.Expected, []byte(actualServerName), "TestSNI: server name mismatch '%s'", test.Name)
		})
	}
}

func TestPionV3CipherSuiteMatchesCertificateType(t *testing.T) {
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name           string
		cipherList     []dtls.CipherSuiteID
		expectedCipher dtls.CipherSuiteID
		generateRSA    bool
	}{
		{
			Name: "ECDSA Certificate with RSA CipherSuite first",
			cipherList: []dtls.CipherSuiteID{
				dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			expectedCipher: dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		{
			Name: "RSA Certificate with ECDSA CipherSuite first",
			cipherList: []dtls.CipherSuiteID{
				dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			expectedCipher: dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
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

func TestPionV3MultipleServerCertificates(t *testing.T) {
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

func TestPionV3SkipHelloVerify(t *testing.T) {
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
		_, sErr = server.Read(buf)
		assert.NoError(t, sErr)
		gotHello <- struct{}{}
		assert.NoError(t, server.Close())
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

	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}
	assert.NoError(t, client.Close())
}

func TestPionV3HelloRandom(t *testing.T) {
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
		_, sErr = server.Read(buf)
		assert.NoError(t, sErr)

		gotHello <- struct{}{}
		assert.NoError(t, server.Close())
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

	case <-time.After(time.Second * 5):
		assert.Fail(t, "timeout")
	}

	assert.NoError(t, client.Close())
}

func TestPionV3OnConnectionAttempt(t *testing.T) {
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

func TestPionV3ConnectionState(t *testing.T) {
	ca, cb := packetPipe()

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := dtls.ClientWithOptions(
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

func TestPionV3MultiHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	ca, cb := packetPipe()
	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	server, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
	assert.NoError(t, err)

	go func() {
		_ = server.Handshake()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	client, err := dtls.ClientWithOptions(ca, ca.RemoteAddr(), dtls.WithCertificates(clientCert))
	assert.NoError(t, err)
	assert.Error(t, client.Handshake())
	assert.Error(t, client.Handshake())
	assert.NoError(t, server.Close())
	assert.NoError(t, client.Close())
}

func TestPionV3CloseDuringHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	for range 100 {
		_, cb := packetPipe()
		server, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
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

func TestPionV3CloseWithoutHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	_, cb := packetPipe()
	server, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(), dtls.WithCertificates(serverCert))
	assert.NoError(t, err)
	assert.NoError(t, server.Close())
}

func TestPionV3DTLS13RetransmittedClientFinalFlight(t *testing.T) {
	t.Skip("Pion v3 does not support DTLS 1.3")
}

func TestPionV3DTLSDualStackClient(t *testing.T) { t.Skip("Pion v3 does not support DTLS 1.3") }

func TestPionV3DTLSDualStackClientRejectsNonClientHelloBeforeWrite(t *testing.T) {
	t.Skip("Pion v3 does not support DTLS 1.3")
}

func TestPionV3DTLSDualStackServer(t *testing.T) { t.Skip("Pion v3 does not support DTLS 1.3") }

func TestPionV3DetachedConnEvents(t *testing.T) {
	t.Skip("Pion v3 does not expose detached connections")
}

func TestPionV3DetachedConnLifecycle(t *testing.T) {
	t.Skip("Pion v3 does not expose detached connections")
}

func TestPionV3DetachedConnCanceledContext(t *testing.T) {
	t.Skip("Pion v3 does not expose detached connections")
}

func TestPionV3DetachedConnAutonomousRetransmit(t *testing.T) {
	t.Skip("Pion v3 does not expose detached connections")
}

func TestPionV3ServerRetainsRejectedTransport(t *testing.T) {
	ca, cb := packetPipe()
	defer func() { _ = ca.Close() }()
	defer func() { _ = cb.Close() }()
	expected := errConnectionAttemptFailed
	_, err := dtls.ServerWithOptions(cb, cb.RemoteAddr(), dtls.WithOnConnectionAttempt(func(net.Addr) error { return expected }))
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
