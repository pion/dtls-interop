// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package pionv3

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

func TestPionV3SimpleReadWrite(t *testing.T) {
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
