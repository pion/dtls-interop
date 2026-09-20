// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/stretchr/testify/require"
)

var errInteropNegotiation = errors.New("unexpected interop negotiation")

func TestBoringSSLInterop(t *testing.T) { runInteropSuite(t, boringSSLInterop()) }

func TestOpenSSL3Interop(t *testing.T) { runInteropSuite(t, openSSLInterop()) }

func TestWolfSSLInterop(t *testing.T) { runInteropSuite(t, wolfSSLInterop()) }

func TestPionV3Interop(t *testing.T) { runInteropSuite(t, pionV3Interop()) }

func (testCase interopCase) checkConnection(connection *dtls.Conn) error {
	state, ok := connection.ConnectionState()
	if !ok || state.NegotiatedVersion() != testCase.version {
		return fmt.Errorf("%w: want version %v, got %v (state available: %t)",
			errInteropNegotiation, testCase.version, state.NegotiatedVersion(), ok)
	}
	if testCase.scenario == interopWebRTC {
		profile, selected := connection.SelectedSRTPProtectionProfile()
		if !selected || profile != dtls.SRTP_AES128_CM_HMAC_SHA1_80 {
			return fmt.Errorf("%w: DTLS-SRTP profile %v (selected: %t)", errInteropNegotiation, profile, selected)
		}
	}

	return nil
}

func skipInterop(reason error, detail string) interopRun {
	return func(*testing.T, interopCase) error {
		return fmt.Errorf("%w: %s", reason, detail)
	}
}

func runInteropSuite(t *testing.T, backend interopBackend) {
	t.Helper()
	for _, testCase := range standardInteropCases() {
		t.Run(testCase.name, func(t *testing.T) {
			err := backend.run(t, testCase)
			if errors.Is(err, errInteropNotSupported) || errors.Is(err, errInteropNotImplemented) {
				t.Skip(err)
			}
			require.NoError(t, err)
		})
	}
}
