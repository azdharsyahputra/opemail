package dovecot

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
		"dovecot.conf",
		filepath.Join("conf.d", "10-mail.conf"),
		filepath.Join("conf.d", "10-auth.conf"),
		filepath.Join("conf.d", "10-master.conf"),
		filepath.Join("conf.d", "auth-sql.conf.ext"),
		filepath.Join("sql", "dovecot-pgsql.conf.ext"),
	}

	for _, f := range files {
		fullPath := filepath.Join(p.configDir, f)
		if _, err := os.Stat(fullPath); err != nil {
			return fmt.Errorf("missing dovecot config file %s: %w", f, err)
		}
	}

	mainConf := filepath.Join(p.configDir, "dovecot.conf")

	// 2. If doveconf CLI is present, run 'doveconf -c <mainConf> -n'
	if _, err := exec.LookPath("doveconf"); err == nil {
		cmd := exec.CommandContext(ctx, "doveconf", "-c", mainConf, "-n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("doveconf validation failed: %s (%w)", stderr.String(), err)
		}
	}

	return nil
}

func (p *systemProvisioner) Reload(ctx context.Context) error {
	if _, err := exec.LookPath("dovecot"); err != nil {
		return errors.New("dovecot binary not found in system PATH")
	}

	mainConf := filepath.Join(p.configDir, "dovecot.conf")
	cmd := exec.CommandContext(ctx, "dovecot", "-c", mainConf, "reload")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dovecot reload failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Start(ctx context.Context) error {
	if _, err := exec.LookPath("dovecot"); err != nil {
		return errors.New("dovecot binary not found in system PATH")
	}

	mainConf := filepath.Join(p.configDir, "dovecot.conf")
	cmd := exec.CommandContext(ctx, "dovecot", "-c", mainConf)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dovecot start failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Stop(ctx context.Context) error {
	if _, err := exec.LookPath("dovecot"); err != nil {
		return errors.New("dovecot binary not found in system PATH")
	}

	mainConf := filepath.Join(p.configDir, "dovecot.conf")
	cmd := exec.CommandContext(ctx, "dovecot", "-c", mainConf, "stop")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dovecot stop failed: %s (%w)", stderr.String(), err)
	}
	return nil
}

func (p *systemProvisioner) Status(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("dovecot"); err != nil {
		return "not installed", nil
	}

	cmd := exec.CommandContext(ctx, "pgrep", "dovecot")
	if err := cmd.Run(); err != nil {
		return "stopped", nil
	}
	return "running", nil
}
