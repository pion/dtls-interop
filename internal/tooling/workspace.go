// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package tooling provides helpers to prepare and run DTLS interop workflows.
package tooling

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	defaultWorkspaceImplementation = "openssl"
	defaultWorkspaceRef            = "main"
)

var (
	errWorkspaceDirMustDiffer = errors.New("--work-dir must differ from --dtls-dir")
	errWorkspaceAlreadyExists = errors.New("workspace already exists")
	errDTLSCheckoutMissing    = errors.New("DTLS checkout does not exist")
	errDTLSGoModMissing       = errors.New("DTLS checkout does not contain go.mod")
)

// PrepareWorkspaceOptions controls how an in-repo DTLS workspace is prepared.
type PrepareWorkspaceOptions struct {
	RepoRoot       string
	DTLSRepo       string
	DTLSDir        string
	DTLSRef        string
	Implementation string
	InRepoDir      string
	Mode           string
	WorkDir        string
	Force          bool
	Stdout         io.Writer
	Stderr         io.Writer
}

// PrepareWorkspaceResult describes the prepared workspace location.
type PrepareWorkspaceResult struct {
	WorkspaceDir string
}

func PrepareInRepoWorkspace(ctx context.Context, opts PrepareWorkspaceOptions) (*PrepareWorkspaceResult, error) {
	opts = normalizePrepareWorkspaceOptions(opts)
	if err := resolveWorkspaceDTLSDir(ctx, &opts); err != nil {
		return nil, err
	}

	workspaceDir, err := absDir(opts.DTLSDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errDTLSCheckoutMissing, opts.DTLSDir)
	}

	if _, err := MaterializeInRepoTests(MaterializeOptions{
		RepoRoot:       opts.RepoRoot,
		DTLSDir:        workspaceDir,
		Implementation: opts.Implementation,
		InRepoDir:      opts.InRepoDir,
		Mode:           opts.Mode,
		Force:          opts.Force,
		Stdout:         opts.Stdout,
	}); err != nil {
		return nil, err
	}

	printLinef(opts.Stdout, "")
	printLinef(opts.Stdout, "DTLS checkout is ready at:")
	printLinef(opts.Stdout, "%s", workspaceDir)

	return &PrepareWorkspaceResult{WorkspaceDir: workspaceDir}, nil
}

func normalizePrepareWorkspaceOptions(opts PrepareWorkspaceOptions) PrepareWorkspaceOptions {
	if opts.Implementation == "" {
		opts.Implementation = defaultWorkspaceImplementation
	}
	if opts.Mode == "" {
		opts.Mode = MaterializeModeLink
	}
	if opts.DTLSRepo == "" {
		opts.DTLSRepo = DefaultDTLSRepo
	}
	if opts.DTLSRef == "" {
		opts.DTLSRef = defaultWorkspaceRef
	}
	if opts.WorkDir == "" {
		opts.WorkDir = filepath.Join(opts.RepoRoot, ".work", "inrepo", opts.Implementation, "dtls")
	}

	return opts
}

func resolveWorkspaceDTLSDir(ctx context.Context, opts *PrepareWorkspaceOptions) error {
	if opts.DTLSDir == "" {
		return prepareWorkspaceFromRef(ctx, opts)
	}

	sourceDir, err := absDir(opts.DTLSDir)
	if err != nil {
		return fmt.Errorf("%w: %s", errDTLSCheckoutMissing, opts.DTLSDir)
	}
	if _, statErr := os.Stat(filepath.Join(sourceDir, "go.mod")); statErr != nil {
		return fmt.Errorf("%w: %s", errDTLSGoModMissing, sourceDir)
	}
	if err = prepareWorkspaceFromDir(sourceDir, opts.WorkDir, opts.Force); err != nil {
		return err
	}

	opts.DTLSDir = opts.WorkDir
	opts.Force = true

	return nil
}

func prepareWorkspaceFromRef(ctx context.Context, opts *PrepareWorkspaceOptions) error {
	if err := os.MkdirAll(filepath.Dir(opts.WorkDir), 0o750); err != nil {
		return err
	}
	if err := ensureClonedWorkspace(ctx, *opts); err != nil {
		return err
	}
	if err := fetchWorkspaceRef(ctx, *opts); err != nil {
		return err
	}

	opts.DTLSDir = opts.WorkDir
	opts.Force = true

	return nil
}

func ensureClonedWorkspace(ctx context.Context, opts PrepareWorkspaceOptions) error {
	_, statErr := os.Stat(filepath.Join(opts.WorkDir, ".git"))
	if os.IsNotExist(statErr) {
		return runCommand(
			ctx,
			"",
			opts.Stdout,
			opts.Stderr,
			nil,
			"git",
			"clone",
			"--no-checkout",
			opts.DTLSRepo,
			opts.WorkDir,
		)
	}
	if statErr != nil {
		return statErr
	}

	return runCommand(
		ctx,
		opts.WorkDir,
		opts.Stdout,
		opts.Stderr,
		nil,
		"git",
		"remote",
		"set-url",
		"origin",
		opts.DTLSRepo,
	)
}

func fetchWorkspaceRef(ctx context.Context, opts PrepareWorkspaceOptions) error {
	if err := runCommand(
		ctx,
		opts.WorkDir,
		opts.Stdout,
		opts.Stderr,
		nil,
		"git",
		"fetch",
		"--force",
		"--tags",
		"origin",
		firstRef(opts.DTLSRef),
	); err != nil {
		return err
	}

	return runCommand(
		ctx,
		opts.WorkDir,
		opts.Stdout,
		opts.Stderr,
		nil,
		"git",
		"checkout",
		"--detach",
		"FETCH_HEAD",
	)
}

func firstRef(raw string) string {
	refs := SplitRefs(raw)
	if len(refs) == 0 {
		return defaultWorkspaceRef
	}

	return refs[0]
}

func prepareWorkspaceFromDir(sourceDir, workDir string, force bool) error {
	targetParent, err := absDir(filepath.Dir(workDir))
	if err != nil {
		if err = os.MkdirAll(filepath.Dir(workDir), 0o750); err != nil {
			return err
		}
		targetParent, err = absDir(filepath.Dir(workDir))
		if err != nil {
			return err
		}
	}

	targetAbs := filepath.Join(targetParent, filepath.Base(workDir))
	if sourceDir == targetAbs {
		return errWorkspaceDirMustDiffer
	}

	_, lstatErr := os.Lstat(targetAbs)
	if lstatErr == nil {
		if !force {
			return fmt.Errorf(
				"%w: %s; rerun with --force or choose --work-dir",
				errWorkspaceAlreadyExists,
				targetAbs,
			)
		}
		if err = os.RemoveAll(targetAbs); err != nil {
			return err
		}
	} else if !os.IsNotExist(lstatErr) {
		return lstatErr
	}

	return copyTree(sourceDir, targetAbs)
}
