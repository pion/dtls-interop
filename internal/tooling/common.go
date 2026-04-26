// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package tooling

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	DefaultDTLSRepo = "https://github.com/pion/dtls.git"
)

var (
	errDirectoryPathRequired = errors.New("directory path is required")
	errNotDirectory          = errors.New("not a directory")
)

func EnvFirst(keys ...string) string {
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			return value
		}
	}

	return ""
}

func SplitRefs(raw string) []string {
	var refs []string
	for field := range strings.FieldsSeq(strings.ReplaceAll(raw, ",", " ")) {
		if field != "" {
			refs = append(refs, field)
		}
	}

	return refs
}

func printLinef(w io.Writer, format string, args ...any) {
	if w == nil {
		w = io.Discard
	}

	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

func absDir(path string) (string, error) {
	if path == "" {
		return "", errDirectoryPathRequired
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: %s", errNotDirectory, abs)
	}

	return abs, nil
}

func runCommand(
	ctx context.Context,
	dir string,
	stdout, stderr io.Writer,
	env []string,
	name string,
	args ...string,
) error {
	//nolint:gosec // Commands and arguments are selected by the interop runner options.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if stdout == nil {
		cmd.Stdout = io.Discard
	} else {
		cmd.Stdout = stdout
	}
	if stderr == nil {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = stderr
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	return nil
}

func commandOutput(
	ctx context.Context,
	dir string,
	stderr io.Writer,
	env []string,
	name string,
	args ...string,
) (string, error) {
	//nolint:gosec // Commands and arguments are selected by the interop runner options.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if stderr == nil {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = stderr
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}

	return strings.TrimSpace(string(output)), nil
}
