// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
)

type runnerMode string

const (
	boringSSL13Mode runnerMode = "boringssl-dtls13"
)

var (
	errUnexpectedArguments = errors.New("unexpected arguments")
	errInvalidTimeout      = errors.New("timeout must be greater than zero")
	errUnknownMode         = errors.New("unknown mode")
)

type commandContextFunc func(context.Context, string, ...string) *exec.Cmd

func runCLI() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, exec.CommandContext); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		_, _ = fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)

		return 1
	}

	return 0
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	flags := flag.NewFlagSet("dtls-interop", flag.ContinueOnError)
	flags.SetOutput(stdout)

	mode := flags.String("mode", string(boringSSL13Mode), "interop mode to run")
	shimPath := flags.String(
		"bssl-shim",
		environmentOrDefault("DTLS_INTEROP_BSSL_SHIM_BIN", "bssl-shim"),
		"path to bssl_shim",
	)
	timeout := flags.Duration("timeout", defaultTimeout, "maximum time for the probe")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: %s", errUnexpectedArguments, strings.Join(flags.Args(), " "))
	}
	if *timeout <= 0 {
		return errInvalidTimeout
	}

	runCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	switch runnerMode(*mode) {
	case boringSSL13Mode:
		if err := probeBoringSSL13(runCtx, *shimPath, stdout, commandContext); err != nil {
			return fmt.Errorf("%s: %w", boringSSL13Mode, err)
		}

		return nil
	default:
		return fmt.Errorf("%w %q", errUnknownMode, *mode)
	}
}

func environmentOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
