// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/protocol"
)

func runBoringSSLCase(t *testing.T, testCase interopCase) error {
	t.Helper()
	config := pionConfigForCase(testCase)
	if testCase.version != protocol.Version1_3 {
		return fmt.Errorf("%w: BoringSSL adapter currently uses DTLS 1.3", errInteropNotImplemented)
	}
	options := boringSSLProbeOptions{
		keyExchangeGroup:      config.peerGroup,
		pionKeyExchangeGroups: config.groups,
	}
	switch testCase.scenario {
	case interopHandshake, interopKeyExchange:
	case interopKeyUpdatePion:
		options.pionKeyUpdate = updatePionKeys
	case interopKeyUpdatePeer:
		options.boringSSLKeyUpdate = true
	default:
		return fmt.Errorf("%w: BoringSSL %s adapter", errInteropNotImplemented, testCase.scenario)
	}
	probe := probeBoringSSL13PionClientWithOptions
	if testCase.role == interopPionServer {
		probe = probeBoringSSL13PionServerWithOptions
	}
	ctx, cancel := context.WithTimeout(t.Context(), defaultTimeout)
	defer cancel()
	var output bytes.Buffer
	err := probe(ctx, environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"),
		&output, exec.CommandContext, options)
	if output.Len() != 0 {
		t.Log(strings.TrimSpace(output.String()))
	}

	return err
}

func updatePionKeys(ctx context.Context, connection *dtls.Conn) error {
	return connection.UpdateKeys(ctx, dtls.KeyUpdateOptions{RequestPeerUpdate: true})
}
