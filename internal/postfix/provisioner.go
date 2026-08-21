package postfix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Provisioner interface {
	Validate(ctx context.Context) error
	Reload(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status(ctx context.Context) (string, error)
}

type systemProvisioner struct {
	configDir string
}

func NewSystemProvisioner(configDir string) Provisioner {
	return &systemProvisioner{
		configDir: configDir,
	}
}

func (p *systemProvisioner) Validate(ctx context.Context) error {
	// 1. Verify existence of generated configuration files
	files := []string{
		"main.cf",
		"master.cf",
		"pgsql-virtual-mailbox-domains.cf",
		"pgsql-virtual-mailbox-maps.cf",
		"pgsql-virtual-alias-maps.cf",
	}

	for _, f := range files {
		fullPath := filepath.Join(p.configDir, f)
		if _, err := os.Stat(fullPath); err != nil {
			return fmt.Errorf("missing postfix config file %s: %w", f, err)
		}
	}

	// 2. If postfix CLI is present and running as root (euid == 0), run 'postfix check'
	if _, err := exec.LookPath("postfix"); err == nil && os.Geteuid() == 0 {
		cmd := exec.CommandContext(ctx, "postfix", "-c", p.configDir, "check")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("postfix check failed: %s (%w)", stderr.String(), err)
		}
	}

	return nil
}

func (p *systemProvisioner) Reload(ctx context.Context) error {
	if _, err := exec.LookPath("postfix"); err != nil {
		return errors.New("postfix binary not found in system PATH")
	}

	cmd := exec.CommandContext(ctx, "postfix", "-c", p.configDir, "reload")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("postfix reload failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Start(ctx context.Context) error {
	if _, err := exec.LookPath("postfix"); err != nil {
		return errors.New("postfix binary not found in system PATH")
	}

	cmd := exec.CommandContext(ctx, "postfix", "-c", p.configDir, "start")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("postfix start failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Stop(ctx context.Context) error {
	if _, err := exec.LookPath("postfix"); err != nil {
		return errors.New("postfix binary not found in system PATH")
	}

	cmd := exec.CommandContext(ctx, "postfix", "-c", p.configDir, "stop")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("postfix stop failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Status(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("postfix"); err != nil {
		return "not installed", nil
	}

	cmd := exec.CommandContext(ctx, "postfix", "-c", p.configDir, "status")
	if err := cmd.Run(); err != nil {
		return "stopped", nil
	}
	return "running", nil
}
