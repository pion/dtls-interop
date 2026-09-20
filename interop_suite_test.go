// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/stretchr/testify/require"
)

func TestStandardInteropCases(t *testing.T) {
	names := map[string]bool{}
	for _, testCase := range standardInteropCases() {
		require.False(t, names[testCase.name], "duplicate case %s", testCase.name)
		names[testCase.name] = true
	}
	for _, version := range []string{"DTLS12", "DTLS13"} {
		for _, role := range []interopRole{interopPionClient, interopPionServer} {
			for group := range elliptic.Curves() {
				for _, mode := range []string{"WithFallback", "WithoutFallback"} {
					name := version + "/" + string(role) + "/KeyExchange/" + mode + "/" + group.String()
					require.True(t, names[name], "missing case %s", name)
				}
			}
		}
	}
}

// Exercise Go's actual PASS/SKIP/FAIL reporting in a child test process, including
// wrapped capability errors and ordinary errors that must never become skips.
func TestInteropSuiteReporting(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skip("subprocesses are unavailable on WebAssembly")
	}

	const helperEnv = "DTLS_INTEROP_REPORTING_TEST"
	if mode := os.Getenv(helperEnv); mode != "" {
		runInteropSuite(t, func(_ *testing.T, _ interopCase) error {
			switch mode {
			case "success":
				return nil
			case "unsupported":
				return fmt.Errorf("%w: test peer capability", errInteropNotSupported)
			case "unimplemented":
				return fmt.Errorf("%w: test adapter capability", errInteropNotImplemented)
			default:
				return io.ErrUnexpectedEOF
			}
		})

		return
	}
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, test := range []struct {
		mode    string
		status  string
		message string
	}{
		{mode: "success", status: "PASS"},
		{mode: "unsupported", status: "SKIP", message: "not supported: test peer capability"},
		{mode: "unimplemented", status: "SKIP", message: "not implemented: test adapter capability"},
		{mode: "failure", status: "FAIL", message: "unexpected EOF"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			command := exec.CommandContext(t.Context(), executable, //nolint:gosec // Re-run this test binary.
				"-test.v", "-test.run=^TestInteropSuiteReporting$/DTLS12/PionClient/Handshake$")
			command.Env = append(os.Environ(), helperEnv+"="+test.mode)
			output, runErr := command.CombinedOutput()
			if test.status == "FAIL" {
				require.Error(t, runErr)
			} else {
				require.NoError(t, runErr, string(output))
			}
			require.Contains(t, string(output), "--- "+test.status+": TestInteropSuiteReporting/DTLS12/PionClient/Handshake")
			if test.message != "" {
				require.Contains(t, string(output), test.message)
			}
		})
	}
}
