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
	Use:   "reviewer-service",
	Short: "Reviewer Agent Service",
	Long:  `Reviewer Agent Service provides document review using AI.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	v = config.InitViper("reviewer-service")
	config.BindFlags(rootCmd, v)
}

func initConfig() {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
}
