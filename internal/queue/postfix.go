package queue

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Driver interface {
	ListQueueRaw(ctx context.Context) (string, error)
	InspectMessage(ctx context.Context, queueID string) (string, error)
	DeleteMessage(ctx context.Context, queueID string) error
	HoldMessage(ctx context.Context, queueID string) error
	ReleaseMessage(ctx context.Context, queueID string) error
	RequeueMessage(ctx context.Context, queueID string) error
	FlushQueue(ctx context.Context) error
}

type SystemDriver struct {
	DockerContainerName string // e.g. mailopen_postfix
}

func NewSystemDriver(dockerContainerName string) *SystemDriver {
	if dockerContainerName == "" {
		dockerContainerName = "mailopen_postfix"
	}
	return &SystemDriver{DockerContainerName: dockerContainerName}
}

func (d *SystemDriver) runCommand(ctx context.Context, name string, args ...string) (string, error) {
	// 1. Try local command first if lookpath succeeds
	if _, err := exec.LookPath(name); err == nil {
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return string(out), nil
		}
		// If local command failed (e.g. host daemon down), try docker container below
	}

	// 2. Fallback to docker exec inside Postfix container
	dockerArgs := append([]string{"exec", d.DockerContainerName, name}, args...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker exec %s %s failed: %w (output: %s)", d.DockerContainerName, name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}


func (d *SystemDriver) ListQueueRaw(ctx context.Context) (string, error) {
	out, err := d.runCommand(ctx, "postqueue", "-p")
	if err != nil && strings.Contains(out, "Mail queue is empty") {
		return out, nil
	}
	return out, err
}

func (d *SystemDriver) InspectMessage(ctx context.Context, queueID string) (string, error) {
	return d.runCommand(ctx, "postcat", "-q", queueID)
}

func (d *SystemDriver) DeleteMessage(ctx context.Context, queueID string) error {
	_, err := d.runCommand(ctx, "postsuper", "-d", queueID)
	return err
}

func (d *SystemDriver) HoldMessage(ctx context.Context, queueID string) error {
	_, err := d.runCommand(ctx, "postsuper", "-h", queueID)
	return err
}

func (d *SystemDriver) ReleaseMessage(ctx context.Context, queueID string) error {
	_, err := d.runCommand(ctx, "postsuper", "-H", queueID)
	return err
}

func (d *SystemDriver) RequeueMessage(ctx context.Context, queueID string) error {
	_, err := d.runCommand(ctx, "postsuper", "-r", queueID)
	return err
}

func (d *SystemDriver) FlushQueue(ctx context.Context) error {
	_, err := d.runCommand(ctx, "postqueue", "-f")
	return err
}
