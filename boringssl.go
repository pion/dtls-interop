// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	dtls13Version = 0xfefc
	shimID        = uint64(1)

	shimExitGracePeriod = time.Second
)

var (
	errEmptyShimPath           = errors.New("bssl_shim path must not be empty")
	errUnexpectedListener      = errors.New("unexpected listener address")
	errUnexpectedShimID        = errors.New("unexpected bssl_shim ID")
	errShimExitedBeforeConnect = errors.New("bssl_shim exited before connecting")
)

type shimProcess struct {
	cancel   context.CancelFunc
	waitDone chan struct{}
	waitErr  error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

func probeBoringSSL13(
	ctx context.Context,
	shimPath string,
	stdout io.Writer,
	commandContext commandContextFunc,
) error {
	if shimPath == "" {
		return errEmptyShimPath
	}

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for bssl_shim: %w", err)
	}
	defer func() { _ = listener.Close() }()

	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("%w: %q", errUnexpectedListener, listener.Addr())
	}

	process, err := startBoringSSLShim(ctx, shimPath, tcpAddress.Port, commandContext)
	if err != nil {
		return err
	}

	waitForShimExit := false
	defer func() { process.stop(waitForShimExit) }()

	connection, err := acceptShimConnection(ctx, listener, process)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()

	if err = readAndValidateShimID(ctx, connection); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		stdout,
		"PASS %s: shim TCP bootstrap connected\n",
		boringSSL13Mode,
	)

	waitForShimExit = true

	return nil
}

func startBoringSSLShim(
	ctx context.Context,
	shimPath string,
	port int,
	commandContext commandContextFunc,
) (*shimProcess, error) {
	childCtx, cancelChild := context.WithCancel(ctx)
	process := &shimProcess{
		cancel:   cancelChild,
		waitDone: make(chan struct{}),
	}
	command := commandContext(
		childCtx,
		shimPath,
		"-port", strconv.Itoa(port),
		"-shim-id", strconv.FormatUint(shimID, 10),
		"-dtls",
		"-min-version", strconv.Itoa(dtls13Version),
		"-max-version", strconv.Itoa(dtls13Version),
	)
	command.Stdout = &process.stdout
	command.Stderr = &process.stderr

	if err := command.Start(); err != nil {
		cancelChild()

		return nil, fmt.Errorf("start bssl_shim: %w", err)
	}

	go func() {
		process.waitErr = command.Wait()
		close(process.waitDone)
	}()

	return process, nil
}

func acceptShimConnection(
	ctx context.Context,
	listener net.Listener,
	process *shimProcess,
) (net.Conn, error) {
	type acceptResult struct {
		connection net.Conn
		err        error
	}

	accepted := make(chan acceptResult, 1)
	go func() {
		connection, err := listener.Accept()
		accepted <- acceptResult{connection: connection, err: err}
	}()

	select {
	case result := <-accepted:
		if result.err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
			}

			return nil, fmt.Errorf("accept bssl_shim TCP connection: %w", result.err)
		}

		return result.connection, nil
	case <-process.waitDone:
		if ctx.Err() != nil {
			return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
		}

		return nil, process.exitError()
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for bssl_shim TCP connection: %w", ctx.Err())
	}
}

func readAndValidateShimID(ctx context.Context, connection net.Conn) error {
	stopCloseOnCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCloseOnCancellation()

	var encodedID [8]byte
	if _, err := io.ReadFull(connection, encodedID[:]); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("read bssl_shim ID: %w", ctx.Err())
		}

		return fmt.Errorf("read bssl_shim ID: %w", err)
	}

	receivedID := binary.LittleEndian.Uint64(encodedID[:])
	if receivedID != shimID {
		return fmt.Errorf("%w: got %d, want %d", errUnexpectedShimID, receivedID, shimID)
	}

	return nil
}

func (process *shimProcess) stop(waitForExit bool) {
	if waitForExit {
		timer := time.NewTimer(shimExitGracePeriod)
		defer timer.Stop()

		select {
		case <-process.waitDone:
			process.cancel()

			return
		case <-timer.C:
		}
	}

	process.cancel()
	<-process.waitDone
}

func (process *shimProcess) exitError() error {
	details := make([]string, 0, 3)
	if process.waitErr != nil {
		details = append(details, "process: "+process.waitErr.Error())
	}
	if output := strings.TrimSpace(process.stdout.String()); output != "" {
		details = append(details, "stdout: "+output)
	}
	if output := strings.TrimSpace(process.stderr.String()); output != "" {
		details = append(details, "stderr: "+output)
	}

	if len(details) == 0 {
		return errShimExitedBeforeConnect
	}

	return fmt.Errorf("%w (%s)", errShimExitedBeforeConnect, strings.Join(details, "; "))
}
