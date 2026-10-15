// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
)

const (
	defaultAnvilTimeout = 8 * time.Minute
	anvilVersion12      = "1.2"
	anvilVersion13      = "1.3"
)

var (
	errAnvilResults = errors.New("TLS-Anvil did not pass")
	errAnvilProfile = errors.New("invalid TLS-Anvil profile")
	errAnvilVersion = errors.New("unsupported Anvil DTLS version (use 1.2 or 1.3)")
)

type anvilOptions struct {
	binary    string
	profile   string
	outputDir string
	version   string
}

type anvilProfile struct {
	Name     string   `json:"name"`
	TestIDs  []string `json:"testIds"`
	Profiles []string `json:"profiles"`
}

//go:embed anvil/profiles/dtls13-server.json
var anvil13Profile []byte

// runAnvil runs TLS-Anvil's native DTLS tests against Pion over UDP.
func runAnvil(ctx context.Context, options anvilOptions, stdout io.Writer, commandContext commandContextFunc) error {
	if options.version == "" {
		options.version = anvilVersion12
	}
	version, err := anvilProtocolVersion(options.version)
	if err != nil {
		return err
	}
	binary, err := anvilBinaryPath(options.binary)
	if err != nil {
		return err
	}
	profile, err := readAnvilProfile(options.profile, options.version)
	if err != nil {
		return err
	}
	runDir, err := prepareAnvilOutput(options.outputDir, profile, options.version)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "TLS-Anvil DTLS %s reports: %s\n", options.version, runDir)
	logFile, err := os.Create(filepath.Join(runDir, "anvil.log")) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()

	listener, err := listenAnvilTarget(version)
	if err != nil {
		return err
	}
	err = runAnvilCommand(ctx, listener, binary, version, runDir, io.MultiWriter(stdout, logFile), commandContext)
	if err != nil {
		return fmt.Errorf("TLS-Anvil (reports: %s): %w", runDir, err)
	}
	if err = checkAnvilResults(filepath.Join(runDir, "result_map.json"), profile.TestIDs...); err != nil {
		return fmt.Errorf("%w (reports: %s)", err, runDir)
	}

	_, _ = fmt.Fprintf(stdout, "TLS-Anvil DTLS %s profile passed\n", options.version)

	return nil
}

func runAnvilCommand(
	ctx context.Context, listener net.Listener, binary string, version protocol.Version,
	runDir string, output io.Writer, commandContext commandContextFunc,
) error {
	runCtx, cancel := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveAnvilTarget(runCtx, listener)
		cancel()
	}()
	defer cancel()

	versionFlag, strength := "-dtls", "1"
	if version == protocol.Version1_3 {
		versionFlag, strength = "-dtls13", "2"
	}
	command := commandContext(runCtx, binary,
		versionFlag, "-parallelTests", "1", "-parallelHandshakes", "1",
		"-strength", strength, "-connectionTimeout", "1000", "-disableTcpDump", "-ignoreCache",
		"-outputFolder", runDir, "-profileFolder", runDir, "-profiles", "profile",
		"server", "-connect", listener.Addr().String(),
	)
	// TLS-Scanner also writes files relative to its working directory.
	command.Dir = runDir
	command.Stdout = output
	command.Stderr = command.Stdout
	command.WaitDelay = time.Second
	commandErr := command.Run()
	cancel()
	serverErr := <-serverDone
	if ctx.Err() != nil {
		return fmt.Errorf("interrupted: %w", ctx.Err())
	}
	if serverErr != nil {
		return fmt.Errorf("pion Anvil target: %w", serverErr)
	}
	if commandErr != nil {
		return fmt.Errorf("run process: %w", commandErr)
	}

	return nil
}

func anvilProtocolVersion(version string) (protocol.Version, error) {
	switch version {
	case anvilVersion12:
		return protocol.Version1_2, nil
	case anvilVersion13:
		return protocol.Version1_3, nil
	default:
		return 0, fmt.Errorf("%w: %q", errAnvilVersion, version)
	}
}

func anvilBinaryPath(binary string) (string, error) {
	if strings.ContainsRune(binary, filepath.Separator) {
		return filepath.Abs(binary)
	}

	return binary, nil
}

func setAnvilTimeout(flags *flag.FlagSet, timeout *time.Duration) {
	explicitTimeout := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "timeout" {
			explicitTimeout = true
		}
	})
	if !explicitTimeout {
		*timeout = defaultAnvilTimeout
	}
}

func readAnvilProfile(path, version string) (anvilProfile, error) {
	if path == "" && version == anvilVersion12 {
		return anvilProfile{Name: "DTLS 1.2 handshake", TestIDs: []string{"5246-jsdAL1vDy5"}, Profiles: []string{}}, nil
	}
	profile := anvil13Profile
	if path != "" {
		var err error
		profile, err = os.ReadFile(path) //nolint:gosec
		if err != nil {
			return anvilProfile{}, fmt.Errorf("read Anvil profile: %w", err)
		}
	}
	var selection anvilProfile
	if err := json.Unmarshal(profile, &selection); err != nil {
		return selection, fmt.Errorf("%w: %w", errAnvilProfile, err)
	}
	if len(selection.TestIDs) == 0 || len(selection.Profiles) != 0 {
		return selection, fmt.Errorf("%w: provide testIds and no nested profiles", errAnvilProfile)
	}
	selection.Profiles = []string{}

	return selection, nil
}

func prepareAnvilOutput(parent string, profile anvilProfile, version string) (string, error) {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", err
	}
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(absParent, 0o750); err != nil {
		return "", err
	}
	runDir, err := os.MkdirTemp(absParent, "dtls"+strings.ReplaceAll(version, ".", "")+"-")
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(runDir, "profile.json"), data, 0o600); err != nil {
		return "", err
	}

	return runDir, nil
}

// Anvil can exit zero despite failed tests. Just treat its result map as authoritative.
func checkAnvilResults(path string, selectedIDs ...string) error {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read TLS-Anvil results: %w", err)
	}
	var results map[string][]string
	if err = json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("decode TLS-Anvil results: %w", err)
	}
	if err = validateAnvilResults(results); err != nil {
		return err
	}
	reported := slices.Concat(results["STRICTLY_SUCCEEDED"], results["CONCEPTUALLY_SUCCEEDED"])
	for _, testID := range selectedIDs {
		if slices.Contains(results["DISABLED"], testID) {
			return fmt.Errorf("%w: selected test disabled: %s", errAnvilResults, testID)
		}
		if !slices.Contains(reported, testID) {
			return fmt.Errorf("%w: missing test: %s", errAnvilResults, testID)
		}
	}

	return nil
}

func validateAnvilResults(results map[string][]string) error {
	passed := 0
	var failures []string
	for outcome, testIDs := range results {
		switch outcome {
		case "STRICTLY_SUCCEEDED", "CONCEPTUALLY_SUCCEEDED":
			passed += len(testIDs)
		case "DISABLED":
		default:
			if len(testIDs) > 0 {
				failures = append(failures, outcome+": "+strings.Join(testIDs, ", "))
			}
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)

		return fmt.Errorf("%w: %s", errAnvilResults, strings.Join(failures, "; "))
	}
	if passed == 0 {
		return fmt.Errorf("%w: no tests succeeded", errAnvilResults)
	}

	return nil
}

func listenAnvilTarget(version protocol.Version) (net.Listener, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	return dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(certificate),
		dtls.WithMinVersion(version),
		dtls.WithMaxVersion(version),
		// Reuse TLS 1.3 workflows that mutate only the initial ClientHello.
		dtls.WithInsecureSkipVerifyHello(version == protocol.Version1_3),
	)
}

func serveAnvilTarget(ctx context.Context, listener net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() { _ = listener.Close() }()
	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return err
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			serveAnvilConnection(ctx, connection)
		}()
	}
}

func serveAnvilConnection(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	// Malformed handshakes and silent peers are expected in a conformance suite.
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	_, _ = io.CopyBuffer(connection, connection, make([]byte, 65535))
}
