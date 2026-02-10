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
	Use:   "document-service",
	Short: "Document Service for SPIFFE/SPIRE Zero Trust Demo",
	Long: `Document Service provides protected document access for the SPIFFE/SPIRE
Zero Trust Demo. It verifies caller identity and queries OPA for authorization.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	v = config.InitViper("document-service")
	config.BindFlags(rootCmd, v)

	// JWT validation flags
	rootCmd.PersistentFlags().Bool("jwt-validation-enabled", false, "Enable JWT access token validation")
	rootCmd.PersistentFlags().String("jwt-issuer-url", "", "JWT issuer URL (Keycloak realm URL)")
	rootCmd.PersistentFlags().String("jwt-expected-audience", "document-service", "Expected JWT audience")

	v.BindPFlag("jwt.validation_enabled", rootCmd.PersistentFlags().Lookup("jwt-validation-enabled"))
	v.BindPFlag("jwt.issuer_url", rootCmd.PersistentFlags().Lookup("jwt-issuer-url"))
	v.BindPFlag("jwt.expected_audience", rootCmd.PersistentFlags().Lookup("jwt-expected-audience"))
}

func initConfig() {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
}
