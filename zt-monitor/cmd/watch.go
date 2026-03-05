package cmd

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/zt-monitor/internal/ui"
)

var (
	namespace  string
	kubeconfig string
)

var rootCmd = &cobra.Command{
	Use:   "zt-monitor",
	Short: "Zero-Trust Flow Visualizer TUI",
	Long: `zt-monitor watches Kubernetes pod logs in real-time and visualizes
the zero-trust authorization flow: token exchanges, delegation,
and access decisions.`,
}

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch zero-trust flow events in real-time",
	Long: `Tails logs from all SPIFFE demo services and renders a live TUI
showing the flow diagram, event stream, and token exchange details.`,
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().StringVarP(&namespace, "namespace", "n", "spiffe-demo",
		"Kubernetes namespace to watch")
	watchCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "",
		"Path to kubeconfig file (default: ~/.kube/config)")

	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	model := ui.NewModel(namespace, kubeconfig)

	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		return err
	}

	return nil
}
