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
	Use:   "opa-service",
	Short: "OPA Service for SPIFFE/SPIRE Zero Trust Demo",
	Long: `OPA Service provides policy evaluation for the SPIFFE/SPIRE Zero Trust Demo.

It evaluates access policies written in Rego, implementing permission intersection
for delegated AI agent access to protected resources.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	v = config.InitViper("opa-service")
	config.BindFlags(rootCmd, v)
}

func initConfig() {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
}
