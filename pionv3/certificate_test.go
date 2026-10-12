// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

func TestPionV3ClientCertificateTypes(t *testing.T) {
	ecCert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	rsaCert, err := selfsign.SelfSign(rsaKey)
	assert.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	edCert, err := selfsign.SelfSign(edKey)
	assert.NoError(t, err)
	for _, tc := range []struct {
		name  string
		types []clientcertificate.Type
		certs []tls.Certificate
		want  [][]byte
	}{
		{
			"RSA request with EC certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{ecCert},
			nil,
		},
		{
			"EC request with RSA certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{rsaCert},
			nil,
		},
		{
			"select matching certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{ecCert, rsaCert},
			rsaCert.Certificate,
		},
		{
			"matching EC certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{ecCert},
			ecCert.Certificate,
		},
		{
			"matching Ed25519 certificate",
			[]clientcertificate.Type{clientcertificate.ECDSASign},
			[]tls.Certificate{edCert},
			edCert.Certificate,
		},
		{
			"RSA request with Ed25519 certificate",
			[]clientcertificate.Type{clientcertificate.RSASign},
			[]tls.Certificate{edCert},
			nil,
		},
		{"unknown certificate type", []clientcertificate.Type{255}, []tls.Certificate{ecCert}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, callback := range []bool{false, true} {
				clientOpts := []dtls.ClientOption{
					dtls.WithInsecureSkipVerify(true),
					dtls.WithCertificates(tc.certs...),
				}
				if callback {
					clientOpts = append(
						clientOpts,
						dtls.WithGetClientCertificate(func(info *dtls.CertificateRequestInfo) (
							*tls.Certificate,
							error,
						) {
							assert.NotNil(t, info.CertificateTypes)
							for i := range tc.certs {
								if info.SupportsCertificate(&tc.certs[i]) == nil {
									return &tc.certs[i], nil
								}
							}

							return &tls.Certificate{}, nil
						}),
					)
				}
				client, server := handshakePair(t, clientOpts, []dtls.ServerOption{
					dtls.WithCertificates(ecCert),
					dtls.WithClientAuth(dtls.RequestClientCert),
					dtls.WithCertificateRequestMessageHook(func(req handshake.MessageCertificateRequest) handshake.Message {
						req.CertificateTypes = tc.types

						return &req
					}),
				})
				assert.NoError(t, client.configErr)
				assert.NoError(t, server.configErr)
				assert.NoError(t, client.handshakeError)
				assert.NoError(t, server.handshakeError)
				state, ok := server.conn.ConnectionState()
				assert.True(t, ok)
				assert.Equal(t, tc.want, state.PeerCertificates)
			}
		})
	}
}
