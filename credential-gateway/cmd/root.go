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
	Use:   "credential-gateway",
	Short: "Credential Gateway for SPIFFE/SPIRE Zero Trust Demo",
	Long: `Credential Gateway translates JWTs with act claims into scoped
service-specific credentials. It validates the delegation chain, queries OPA
for the permission intersection, and returns temporary credentials (e.g., AWS
STS session tokens) restricted to the intersection.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")

	v = config.InitViper("credential-gateway")
	config.BindFlags(rootCmd, v)

	// JWT validation flags
	rootCmd.PersistentFlags().Bool("jwt-validation-enabled", false, "Enable JWT access token validation")
	rootCmd.PersistentFlags().String("jwt-issuer-url", "", "JWT issuer URL (Keycloak realm URL)")
	rootCmd.PersistentFlags().String("jwt-expected-audience", "credential-gateway", "Expected JWT audience")

	v.BindPFlag("jwt.validation_enabled", rootCmd.PersistentFlags().Lookup("jwt-validation-enabled"))
	v.BindPFlag("jwt.issuer_url", rootCmd.PersistentFlags().Lookup("jwt-issuer-url"))
	v.BindPFlag("jwt.expected_audience", rootCmd.PersistentFlags().Lookup("jwt-expected-audience"))

	// AWS STS flags
	rootCmd.PersistentFlags().String("aws-role-arn", "", "IAM role ARN for STS AssumeRole")
	rootCmd.PersistentFlags().String("aws-region", "us-east-1", "AWS region")
	rootCmd.PersistentFlags().String("s3-bucket", "", "S3 bucket name for session policy ARNs")
	rootCmd.PersistentFlags().Int("sts-duration", 900, "STS session duration in seconds")

	v.BindPFlag("aws.role_arn", rootCmd.PersistentFlags().Lookup("aws-role-arn"))
	v.BindPFlag("aws.region", rootCmd.PersistentFlags().Lookup("aws-region"))
	v.BindPFlag("aws.s3_bucket", rootCmd.PersistentFlags().Lookup("s3-bucket"))
	v.BindPFlag("aws.sts_duration", rootCmd.PersistentFlags().Lookup("sts-duration"))
}

func initConfig() {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
}
