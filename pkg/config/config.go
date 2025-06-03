package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	// "strings" // Removed as it's unused
)

// Settings holds all configurable settings
type Settings struct {
	CPUProfile      string `json:"cpuprofile"`
	LogLevel        string `json:"loglevel"`
	LogFile         string `json:"logfile"`
	Compress        bool   `json:"compress"`
	TSIG            string `json:"tsig"`
	SOReusePort     int    `json:"soreuseport"`
	CPU             int    `json:"cpu"`
	BaseDomain      string `json:"basedomain"`
	CacheLimit      int64  `json:"cachelimit"`
	DNSServers      string `json:"dnsservers"`
	VoidLookupLimit uint   `json:"voidlookuplimit"`
	CacheTTL        int    `json:"cachettl"`
	MaxConcurrent   int    `json:"maxconcurrent"`
	MetricsPort     int    `json:"metricsport"`
}

// Flags holds the command-line flags
type Flags struct {
	CPUProfile      *string
	LogLevel        *string
	LogFile         *string
	Compress        *bool
	TSIG            *string
	SOReusePort     *int
	CPU             *int
	BaseDomain      *string
	CacheLimit      *int64
	DNSServers      *string
	VoidLookupLimit *uint
	CacheTTL        *int
	MaxConcurrent   *int
	MetricsPort     *int
}

func envString(envKey, defaultValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return defaultValue
}

func envBool(envKey string, defaultValue bool) bool {
	if value := os.Getenv(envKey); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func envInt(envKey string, defaultValue int) int {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func envInt64(envKey string, defaultValue int64) int64 {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func envUint(envKey string, defaultValue uint) uint {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint(i)
		}
	}
	return defaultValue
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// LoadEnvConfig loads configuration from environment variables, respecting command-line flags.
func LoadEnvConfig(f *Flags) {
	if !isFlagSet("cpuprofile") {
		*f.CPUProfile = envString("SPFFY_CPUPROFILE", *f.CPUProfile)
	}
	if !isFlagSet("loglevel") {
		*f.LogLevel = envString("SPFFY_LOGLEVEL", *f.LogLevel)
	}
	if !isFlagSet("logfile") {
		*f.LogFile = envString("SPFFY_LOGFILE", *f.LogFile)
	}
	if !isFlagSet("compress") {
		*f.Compress = envBool("SPFFY_COMPRESS", *f.Compress)
	}
	if !isFlagSet("tsig") {
		*f.TSIG = envString("SPFFY_TSIG", *f.TSIG)
	}
	if !isFlagSet("soreuseport") {
		*f.SOReusePort = envInt("SPFFY_SOREUSEPORT", *f.SOReusePort)
	}
	if !isFlagSet("cpu") {
		*f.CPU = envInt("SPFFY_CPU", *f.CPU)
	}
	if !isFlagSet("basedomain") {
		*f.BaseDomain = envString("SPFFY_BASEDOMAIN", *f.BaseDomain)
	}
	if !isFlagSet("cachelimit") {
		*f.CacheLimit = envInt64("SPFFY_CACHELIMIT", *f.CacheLimit)
	}
	if !isFlagSet("dnsservers") {
		*f.DNSServers = envString("SPFFY_DNSSERVERS", *f.DNSServers)
	}
	if !isFlagSet("voidlookuplimit") {
		*f.VoidLookupLimit = envUint("SPFFY_VOIDLOOKUPLIMIT", *f.VoidLookupLimit)
	}
	if !isFlagSet("cachettl") {
		*f.CacheTTL = envInt("SPFFY_CACHETTL", *f.CacheTTL)
	}
	if !isFlagSet("maxconcurrent") {
		*f.MaxConcurrent = envInt("SPFFY_MAXCONCURRENT", *f.MaxConcurrent)
	}
	if !isFlagSet("metricsport") {
		*f.MetricsPort = envInt("SPFFY_METRICSPORT", *f.MetricsPort)
	}
}

// PrintConfig prints the current configuration using a logger interface.
// As the logger is not part of this package, it needs to be passed in.
// This function is a placeholder and might need adjustment based on how logging is handled.
func PrintConfig(f *Flags, logFunc func(msg map[string]interface{})) {
	logFunc(map[string]interface{}{
		"message": "Configuration",
		"config": map[string]interface{}{
			"SPFFY_CPUPROFILE":      *f.CPUProfile,
			"SPFFY_LOGLEVEL":        *f.LogLevel,
			"SPFFY_LOGFILE":         *f.LogFile,
			"SPFFY_COMPRESS":        *f.Compress,
			"SPFFY_TSIG":            *f.TSIG,
			"SPFFY_SOREUSEPORT":     *f.SOReusePort,
			"SPFFY_CPU":             *f.CPU,
			"SPFFY_BASEDOMAIN":      *f.BaseDomain,
			"SPFFY_CACHELIMIT":      *f.CacheLimit,
			"SPFFY_DNSSERVERS":      *f.DNSServers,
			"SPFFY_VOIDLOOKUPLIMIT": *f.VoidLookupLimit,
			"SPFFY_CACHETTL":        *f.CacheTTL,
			"SPFFY_MAXCONCURRENT":   *f.MaxConcurrent,
			"SPFFY_METRICSPORT":     *f.MetricsPort,
		},
	})
}

// GetInitialSettings creates and initializes a Flags struct with default values and command-line parsing.
func GetInitialSettings() *Flags {
	f := &Flags{
		CPUProfile:      flag.String("cpuprofile", "", "write cpu profile to file"),
		LogLevel:        flag.String("loglevel", "INFO", "log level: NONE, INFO, DEBUG, TRACE"),
		LogFile:         flag.String("logfile", "", "write JSON logs to file (default: stdout)"),
		Compress:        flag.Bool("compress", false, "compress replies"),
		TSIG:            flag.String("tsig", "", "use SHA256 hmac tsig: keyname:base64"),
		SOReusePort:     flag.Int("soreuseport", 0, "number of server instances to start with SO_REUSEPORT (0 to disable)"),
		CPU:             flag.Int("cpu", 0, "number of cpu to use"),
		BaseDomain:      flag.String("basedomain", "_spf-stage.spffy.dev", "base domain for SPF macro queries"),
		CacheLimit:      flag.Int64("cachelimit", 1024*1024*1024, "cache memory limit in bytes (default: 1GB)"),
		DNSServers:      flag.String("dnsservers", "", "comma-separated list of DNS servers to use for lookups (default: system resolver)"),
		VoidLookupLimit: flag.Uint("voidlookuplimit", 20, "maximum number of void DNS lookups allowed during SPF evaluation"),
		CacheTTL:        flag.Int("cachettl", 15, "cache TTL for SPF results in seconds"),
		MaxConcurrent:   flag.Int("maxconcurrent", 1000, "maximum concurrent SPF lookups"),
		MetricsPort:     flag.Int("metricsport", 8080, "port for metrics server"),
	}

	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println("\nEnvironment Variables:")
		fmt.Println("  All flags can also be set via environment variables with SPFFY_ prefix:")
		fmt.Println("  SPFFY_CPUPROFILE, SPFFY_LOGLEVEL, SPFFY_LOGFILE, SPFFY_COMPRESS,")
		fmt.Println("  SPFFY_TSIG, SPFFY_SOREUSEPORT, SPFFY_CPU, SPFFY_BASEDOMAIN,")
		fmt.Println("  SPFFY_CACHELIMIT, SPFFY_DNSSERVERS, SPFFY_VOIDLOOKUPLIMIT,")
		fmt.Println("  SPFFY_CACHETTL, SPFFY_MAXCONCURRENT, SPFFY_METRICSPORT")
		fmt.Println("\nDNS Servers:")
		fmt.Println("  Use comma-separated list for multiple servers (load balanced).")
		fmt.Println("  Example: SPFFY_DNSSERVERS=8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
		fmt.Println("  If not specified, system resolver is used.")
		fmt.Println("\nSO_REUSEPORT:")
		fmt.Println("  Set soreuseport to the number of server instances to start.")
		fmt.Println("  Each instance uses SO_REUSEPORT to share the same port, enabling kernel-level load balancing.")
		fmt.Println("  Example: SPFFY_SOREUSEPORT=4 starts 4 TCP and 4 UDP servers.")
		fmt.Println("\nLogs Endpoint:")
		fmt.Println("  Access /logs on the metrics port to view streaming logs in the browser.")
		fmt.Println("\nSettings Endpoint:")
		fmt.Println("  GET /settings to view current settings as JSON.")
		fmt.Println("  POST /settings with JSON to update settings dynamically.")
	}
	flag.Parse()
	LoadEnvConfig(f)
	return f
}
