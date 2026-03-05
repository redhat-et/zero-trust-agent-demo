package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ServiceConfig holds common service configuration
type ServiceConfig struct {
	Port           int    `mapstructure:"port"`
	HealthPort     int    `mapstructure:"health_port"`
	Host           string `mapstructure:"host"`
	MockSPIFFE     bool   `mapstructure:"mock_spiffe"`
	ListenPlainHTTP bool  `mapstructure:"listen_plain_http"`
	LogLevel       string `mapstructure:"log_level"`
}

// HealthAddr returns the health check listen address (plain HTTP)
func (c ServiceConfig) HealthAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.HealthPort)
}

// SPIFFEConfig holds SPIFFE-related configuration
type SPIFFEConfig struct {
	SocketPath  string `mapstructure:"socket_path"`
	TrustDomain string `mapstructure:"trust_domain"`
}

// OTelConfig holds OpenTelemetry configuration
type OTelConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	CollectorEndpoint string `mapstructure:"collector_endpoint"`
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

// StorageConfig holds S3-compatible object storage configuration
type StorageConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	BucketHost  string `mapstructure:"bucket_host"`
	BucketPort  int    `mapstructure:"bucket_port"`
	BucketName  string `mapstructure:"bucket_name"`
	UseSSL      bool   `mapstructure:"use_ssl"`
	InsecureTLS bool   `mapstructure:"insecure_tls"`
	Region      string `mapstructure:"region"`
}

// CommonConfig holds configuration common to all services
type CommonConfig struct {
	Service ServiceConfig `mapstructure:"service"`
	SPIFFE  SPIFFEConfig  `mapstructure:"spiffe"`
	OPA     OPAConfig     `mapstructure:"opa"`
	OTel    OTelConfig    `mapstructure:"otel"`
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
	v.SetDefault("service.listen_plain_http", false)
	v.SetDefault("service.log_level", "info")

	// Port defaults: AI agent services use Kagenti convention (8000/8100),
	// all other infrastructure services use 8080/8180.
	switch serviceName {
	case "summarizer-service", "reviewer-service":
		v.SetDefault("service.port", 8000)
		v.SetDefault("service.health_port", 8100)
	default:
		v.SetDefault("service.port", 8080)
		v.SetDefault("service.health_port", 8180)
	}

	// SPIFFE defaults
	v.SetDefault("spiffe.socket_path", "/run/spire/sockets/agent.sock")
	v.SetDefault("spiffe.trust_domain", "demo.example.com")

	// OPA defaults
	v.SetDefault("opa.host", "localhost")
	v.SetDefault("opa.port", 8080)

	// OTel defaults
	v.SetDefault("otel.enabled", false)
	v.SetDefault("otel.collector_endpoint", "")

	// Storage defaults (disabled by default for local development)
	v.SetDefault("storage.enabled", false)
	v.SetDefault("storage.bucket_host", "localhost")
	v.SetDefault("storage.bucket_port", 9000)
	v.SetDefault("storage.bucket_name", "documents")
	v.SetDefault("storage.use_ssl", false)
	v.SetDefault("storage.insecure_tls", false)
	v.SetDefault("storage.region", "us-east-1")
}

// Load reads the configuration from file and environment
func Load(v *viper.Viper, cfg any) error {
	// Support standard PORT/HOST env vars used by container platforms (e.g. Kagenti)
	if portStr := os.Getenv("PORT"); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			v.Set("service.port", port)
		}
	}
	if host := os.Getenv("HOST"); host != "" {
		v.Set("service.host", host)
	}

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
	cmd.PersistentFlags().Bool("listen-plain-http", false, "Listen on plain HTTP instead of mTLS (for use behind Envoy proxy)")
	cmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	cmd.PersistentFlags().String("opa-host", "", "OPA service host")
	cmd.PersistentFlags().Int("opa-port", 0, "OPA service port")

	v.BindPFlag("service.port", cmd.PersistentFlags().Lookup("port"))
	v.BindPFlag("service.host", cmd.PersistentFlags().Lookup("host"))
	v.BindPFlag("service.mock_spiffe", cmd.PersistentFlags().Lookup("mock-spiffe"))
	v.BindPFlag("service.listen_plain_http", cmd.PersistentFlags().Lookup("listen-plain-http"))
	v.BindPFlag("service.log_level", cmd.PersistentFlags().Lookup("log-level"))
	cmd.PersistentFlags().Bool("otel-enabled", false, "Enable OpenTelemetry tracing")
	cmd.PersistentFlags().String("otel-collector-endpoint", "", "OpenTelemetry collector gRPC endpoint (e.g. localhost:4317)")

	v.BindPFlag("opa.host", cmd.PersistentFlags().Lookup("opa-host"))
	v.BindPFlag("opa.port", cmd.PersistentFlags().Lookup("opa-port"))
	v.BindPFlag("otel.enabled", cmd.PersistentFlags().Lookup("otel-enabled"))
	v.BindPFlag("otel.collector_endpoint", cmd.PersistentFlags().Lookup("otel-collector-endpoint"))
}

// GetServiceEndpoints returns the default service endpoints for local development
func GetServiceEndpoints() map[string]string {
	return map[string]string{
		"dashboard":   "http://localhost:8080",
		"user":        "http://localhost:8080",
		"agent":       "http://localhost:8080",
		"document":    "http://localhost:8080",
		"opa":         "http://localhost:8080",
		"summarizer":  "http://localhost:8000",
		"reviewer":    "http://localhost:8000",
		"spire-agent": "unix:///run/spire/sockets/agent.sock",
	}
}

// LoadStorageConfigFromEnv loads storage configuration from OBC-style environment variables.
// This supplements the viper config by checking for BUCKET_HOST, BUCKET_PORT, BUCKET_NAME
// which are set by OpenShift OBC ConfigMaps.
func LoadStorageConfigFromEnv(cfg *StorageConfig) {
	if host := os.Getenv("BUCKET_HOST"); host != "" {
		cfg.BucketHost = host
	}
	if portStr := os.Getenv("BUCKET_PORT"); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			cfg.BucketPort = port
		}
	}
	if name := os.Getenv("BUCKET_NAME"); name != "" {
		cfg.BucketName = name
	}
	if region := os.Getenv("BUCKET_REGION"); region != "" {
		cfg.Region = region
	}

	// Auto-detect SSL based on port (443 = HTTPS, typical for NooBaa/ODF)
	// Can be overridden by explicit BUCKET_SSL environment variable
	if sslStr := os.Getenv("BUCKET_SSL"); sslStr != "" {
		cfg.UseSSL = sslStr == "true" || sslStr == "1"
	} else if cfg.BucketPort == 443 {
		cfg.UseSSL = true
	}

	// Handle insecure TLS (skip certificate verification)
	// Auto-enable for internal OpenShift services (*.svc hostnames)
	if insecureStr := os.Getenv("BUCKET_INSECURE_TLS"); insecureStr != "" {
		cfg.InsecureTLS = insecureStr == "true" || insecureStr == "1"
	} else if strings.HasSuffix(cfg.BucketHost, ".svc") {
		// Internal Kubernetes services typically use self-signed certs
		cfg.InsecureTLS = true
	}
}
