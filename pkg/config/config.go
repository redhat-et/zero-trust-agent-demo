package config

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ServiceConfig holds common service configuration
type ServiceConfig struct {
	Port       int    `mapstructure:"port"`
	Host       string `mapstructure:"host"`
	MockSPIFFE bool   `mapstructure:"mock_spiffe"`
	LogLevel   string `mapstructure:"log_level"`
}

// SPIFFEConfig holds SPIFFE-related configuration
type SPIFFEConfig struct {
	SocketPath  string `mapstructure:"socket_path"`
	TrustDomain string `mapstructure:"trust_domain"`
}

// OPAConfig holds OPA service configuration
type OPAConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// Addr returns the OPA service address
func (c OPAConfig) Addr() string {
	return fmt.Sprintf("http://%s:%d", c.Host, c.Port)
}

// CommonConfig holds configuration common to all services
type CommonConfig struct {
	Service ServiceConfig `mapstructure:"service"`
	SPIFFE  SPIFFEConfig  `mapstructure:"spiffe"`
	OPA     OPAConfig     `mapstructure:"opa"`
}

// Addr returns the service listen address
func (c ServiceConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// InitViper initializes Viper with common settings
func InitViper(serviceName string) *viper.Viper {
	v := viper.New()

	// Set config file name and paths
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath(fmt.Sprintf("./%s", serviceName))
	v.AddConfigPath("/etc/spiffe-demo/")

	// Environment variable settings
	v.SetEnvPrefix("SPIFFE_DEMO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Set defaults
	setDefaults(v, serviceName)

	return v
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper, serviceName string) {
	// Service defaults
	v.SetDefault("service.host", "0.0.0.0")
	v.SetDefault("service.mock_spiffe", true)
	v.SetDefault("service.log_level", "info")

	// Port defaults based on service name
	switch serviceName {
	case "web-dashboard":
		v.SetDefault("service.port", 8080)
	case "user-service":
		v.SetDefault("service.port", 8082)
	case "agent-service":
		v.SetDefault("service.port", 8083)
	case "document-service":
		v.SetDefault("service.port", 8084)
	case "opa-service":
		v.SetDefault("service.port", 8085)
	default:
		v.SetDefault("service.port", 8080)
	}

	// SPIFFE defaults
	v.SetDefault("spiffe.socket_path", "/run/spire/sockets/agent.sock")
	v.SetDefault("spiffe.trust_domain", "demo.example.com")

	// OPA defaults
	v.SetDefault("opa.host", "localhost")
	v.SetDefault("opa.port", 8085)
}

// Load reads the configuration from file and environment
func Load(v *viper.Viper, cfg interface{}) error {
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found; use defaults
	}

	if err := v.Unmarshal(cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// BindFlags binds common CLI flags to Viper
func BindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.PersistentFlags().IntP("port", "p", 0, "Port to listen on")
	cmd.PersistentFlags().String("host", "", "Host to bind to")
	cmd.PersistentFlags().Bool("mock-spiffe", true, "Use mock SPIFFE mode (no SPIRE required)")
	cmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	cmd.PersistentFlags().String("opa-host", "", "OPA service host")
	cmd.PersistentFlags().Int("opa-port", 0, "OPA service port")

	v.BindPFlag("service.port", cmd.PersistentFlags().Lookup("port"))
	v.BindPFlag("service.host", cmd.PersistentFlags().Lookup("host"))
	v.BindPFlag("service.mock_spiffe", cmd.PersistentFlags().Lookup("mock-spiffe"))
	v.BindPFlag("service.log_level", cmd.PersistentFlags().Lookup("log-level"))
	v.BindPFlag("opa.host", cmd.PersistentFlags().Lookup("opa-host"))
	v.BindPFlag("opa.port", cmd.PersistentFlags().Lookup("opa-port"))
}

// GetServiceEndpoints returns the default service endpoints for local development
func GetServiceEndpoints() map[string]string {
	return map[string]string{
		"dashboard":   "http://localhost:8080",
		"user":        "http://localhost:8082",
		"agent":       "http://localhost:8083",
		"document":    "http://localhost:8084",
		"opa":         "http://localhost:8085",
		"spire-agent": "unix:///run/spire/sockets/agent.sock",
	}
}
