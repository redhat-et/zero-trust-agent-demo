package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
)

var (
	cfgFile string
	v       *viper.Viper
)

var rootCmd = &cobra.Command{
	Use:   "agent-service",
	Short: "Agent Service for SPIFFE/SPIRE Zero Trust Demo",
	Long: `Agent Service simulates AI agent workloads that act on behalf of users
with delegated permissions.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	v = config.InitViper("agent-service")
	config.BindFlags(rootCmd, v)
}

func initConfig() {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
}
