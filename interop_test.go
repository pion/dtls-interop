// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build interop

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/pion/dtls/v4"
	"github.com/stretchr/testify/require"
)

var errInteropNegotiation = errors.New("unexpected interop negotiation")

func TestBoringSSLInterop(t *testing.T) { runInteropSuite(t, boringSSLInterop()) }

func TestOpenSSL3Interop(t *testing.T) { runInteropSuite(t, openSSLInterop("3")) }

func TestOpenSSL4Interop(t *testing.T) { runInteropSuite(t, openSSLInterop("4")) }

func TestWolfSSLInterop(t *testing.T) { runInteropSuite(t, wolfSSLInterop()) }

func TestPionV3Interop(t *testing.T) { runInteropSuite(t, pionV3Interop()) }

func TestPionV4Interop(t *testing.T) { runInteropSuite(t, pionV4Interop()) }

func TestMbedTLSInterop(t *testing.T) { runInteropSuite(t, mbedTLSInterop()) }

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

type interopProcess struct {
	stdin    io.WriteCloser
	output   interopOutput
	waitDone chan struct{}
}

type interopOutput struct {
	mutex   sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func startInteropProcess(t *testing.T, ctx context.Context, path string, arguments ...string) *interopProcess {
	t.Helper()

	childCtx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(childCtx, path, arguments...) //nolint:gosec
	process := &interopProcess{
		output:   interopOutput{changed: make(chan struct{}, 1)},
		waitDone: make(chan struct{}),
	}
	command.Stdout = &process.output
	command.Stderr = &process.output
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
	}
	require.NoError(t, err)
	process.stdin = stdin
	err = command.Start()
	if err != nil {
		cancel()
		_ = stdin.Close()
	}
	require.NoError(t, err, "start interop peer")
	go func() {
		_ = command.Wait()
		close(process.waitDone)
	}()
	t.Cleanup(func() {
		cancel()
		_ = stdin.Close()
		<-process.waitDone
		if t.Failed() {
			t.Log(process.output.String())
		}
	})

	return process
}

func (process *interopProcess) waitForOutput(t *testing.T, ctx context.Context, expected string) {
	t.Helper()

	for !strings.Contains(process.output.String(), expected) {
		select {
		case <-process.output.changed:
		case <-process.waitDone:
			require.FailNowf(t, "interop peer exited before expected output",
				"want %q, got %s", expected, process.output.String())
		case <-ctx.Done():
			require.NoErrorf(t, ctx.Err(), "wait for interop peer output %q: %s", expected, process.output.String())
		}
	}
}

func (output *interopOutput) Write(payload []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()

	written, err := output.buffer.Write(payload)
	select {
	case output.changed <- struct{}{}:
	default:
	}

	return written, err
}

func (output *interopOutput) String() string {
	output.mutex.Lock()
	defer output.mutex.Unlock()

	return output.buffer.String()
}

func exchangeInteropData(t *testing.T, sender, receiver net.Conn, message string) {
	t.Helper()
	written, err := io.WriteString(sender, message)
	require.NoError(t, err)
	require.Equal(t, len(message), written)
	received := make([]byte, len(message))
	_, err = io.ReadFull(receiver, received)
	require.NoError(t, err)
	require.Equal(t, message, string(received))
}
