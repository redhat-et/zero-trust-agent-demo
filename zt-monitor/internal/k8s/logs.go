package k8s

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/parser"
)

// PodTarget describes a pod + container to tail logs from.
type PodTarget struct {
	Label     string // e.g., "app=agent-service"
	Container string // e.g., "agent-service" or "envoy-proxy"
	IsEnvoy   bool   // true for envoy ext-proc containers
}

// DefaultTargets returns the standard set of pods/containers to monitor.
func DefaultTargets() []PodTarget {
	return []PodTarget{
		{Label: "app=user-service", Container: "user-service"},
		{Label: "app=agent-service", Container: "agent-service"},
		{Label: "app=agent-service", Container: "envoy-proxy", IsEnvoy: true},
		{Label: "app=document-service", Container: "document-service"},
		{Label: "app=summarizer-service", Container: "summarizer-service"},
		{Label: "app=summarizer-service", Container: "envoy-proxy", IsEnvoy: true},
		{Label: "app=reviewer-service", Container: "reviewer-service"},
		{Label: "app=reviewer-service", Container: "envoy-proxy", IsEnvoy: true},
	}
}

// StreamLogs starts tailing logs from all targets and sends parsed events
// to the provided channel. It blocks until ctx is cancelled. Each target
// runs in its own goroutine with automatic reconnection.
func StreamLogs(ctx context.Context, namespace, kubeconfig string, events chan<- parser.Event) {
	targets := DefaultTargets()
	for _, t := range targets {
		go tailTarget(ctx, namespace, kubeconfig, t, events)
	}
}

func tailTarget(ctx context.Context, namespace, kubeconfig string, target PodTarget, events chan<- parser.Event) {
	source := serviceFromLabel(target.Label)

	for {
		if ctx.Err() != nil {
			return
		}

		err := tailOnce(ctx, namespace, kubeconfig, target, source, events)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Debug("log stream ended, reconnecting",
				"target", target.Label,
				"container", target.Container,
				"error", err,
			)
		}

		// Back off before reconnecting
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func tailOnce(ctx context.Context, namespace, kubeconfig string, target PodTarget, source string, events chan<- parser.Event) error {
	args := []string{
		"logs", "-f", "--tail=50",
		"-n", namespace,
		"-l", target.Label,
		"-c", target.Container,
	}
	if kubeconfig != "" {
		args = append([]string{"--kubeconfig", kubeconfig}, args...)
	}

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start kubectl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var ev *parser.Event
		if target.IsEnvoy {
			ev = parser.ParseEnvoyLog(line, source)
		} else {
			ev = parser.ParseServiceLog(line, source)
		}

		if ev != nil && ev.Type != parser.EventUnknown {
			ev.Container = target.Container
			select {
			case events <- *ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return cmd.Wait()
}

func serviceFromLabel(label string) string {
	// "app=agent-service" -> "agent-service"
	parts := strings.SplitN(label, "=", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return label
}
