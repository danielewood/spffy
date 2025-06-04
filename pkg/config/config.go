package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
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
	TCPAddr         string `json:"tcpaddr"`
	UDPAddr         string `json:"udpaddr"`
	RedisAddr       string `json:"redisaddr"`
	RedisPassword   string `json:"redispassword"`
	RedisDB         int    `json:"redisdb"`
	CacheType       string `json:"cachetype"`
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
	TCPAddr         *string
	UDPAddr         *string
	RedisAddr       *string
	RedisPassword   *string
	RedisDB         *int
	CacheType       *string
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

func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// LoadEnvConfig loads configuration from environment variables, respecting command-line flags.
func LoadEnvConfig(f *Flags, fs *flag.FlagSet) {
	if !isFlagSet(fs, "cpuprofile") {
		*f.CPUProfile = envString("SPFFY_CPUPROFILE", *f.CPUProfile)
	}
	if !isFlagSet(fs, "loglevel") {
		*f.LogLevel = envString("SPFFY_LOGLEVEL", *f.LogLevel)
	}
	if !isFlagSet(fs, "logfile") {
		*f.LogFile = envString("SPFFY_LOGFILE", *f.LogFile)
	}
	if !isFlagSet(fs, "compress") {
		*f.Compress = envBool("SPFFY_COMPRESS", *f.Compress)
	}
	if !isFlagSet(fs, "tsig") {
		*f.TSIG = envString("SPFFY_TSIG", *f.TSIG)
	}
	if !isFlagSet(fs, "soreuseport") {
		*f.SOReusePort = envInt("SPFFY_SOREUSEPORT", *f.SOReusePort)
	}
	if !isFlagSet(fs, "cpu") {
		*f.CPU = envInt("SPFFY_CPU", *f.CPU)
	}
	if !isFlagSet(fs, "basedomain") {
		*f.BaseDomain = envString("SPFFY_BASEDOMAIN", *f.BaseDomain)
	}
	if !isFlagSet(fs, "cachelimit") {
		*f.CacheLimit = envInt64("SPFFY_CACHELIMIT", *f.CacheLimit)
	}
	if !isFlagSet(fs, "dnsservers") {
		*f.DNSServers = envString("SPFFY_DNSSERVERS", *f.DNSServers)
	}
	if !isFlagSet(fs, "voidlookuplimit") {
		*f.VoidLookupLimit = envUint("SPFFY_VOIDLOOKUPLIMIT", *f.VoidLookupLimit)
	}
	if !isFlagSet(fs, "cachettl") {
		*f.CacheTTL = envInt("SPFFY_CACHETTL", *f.CacheTTL)
	}
	if !isFlagSet(fs, "maxconcurrent") {
		*f.MaxConcurrent = envInt("SPFFY_MAXCONCURRENT", *f.MaxConcurrent)
	}
	if !isFlagSet(fs, "metricsport") {
		*f.MetricsPort = envInt("SPFFY_METRICSPORT", *f.MetricsPort)
	}
	if !isFlagSet(fs, "tcpaddr") {
		*f.TCPAddr = envString("SPFFY_TCPADDR", *f.TCPAddr)
	}
	if !isFlagSet(fs, "udpaddr") {
		*f.UDPAddr = envString("SPFFY_UDPADDR", *f.UDPAddr)
	}
	if !isFlagSet(fs, "redisaddr") {
		*f.RedisAddr = envString("SPFFY_REDIS_ADDR", *f.RedisAddr)
	}
	if !isFlagSet(fs, "redispassword") {
		*f.RedisPassword = envString("SPFFY_REDIS_PASSWORD", *f.RedisPassword)
	}
	if !isFlagSet(fs, "redisdb") {
		*f.RedisDB = envInt("SPFFY_REDIS_DB", *f.RedisDB)
	}
	if !isFlagSet(fs, "cachetype") {
		*f.CacheType = envString("SPFFY_CACHE_TYPE", *f.CacheType)
	}
}

// PrintConfig prints the current configuration using a logger interface.
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
			"SPFFY_TCPADDR":         *f.TCPAddr,
			"SPFFY_UDPADDR":         *f.UDPAddr,
			"SPFFY_REDIS_ADDR":      *f.RedisAddr,
			"SPFFY_REDIS_PASSWORD":  *f.RedisPassword,
			"SPFFY_REDIS_DB":        *f.RedisDB,
			"SPFFY_CACHE_TYPE":      *f.CacheType,
		},
	})
}

// GetInitialSettings creates and initializes a Flags struct with default values and command-line parsing.
func GetInitialSettings() *Flags {
	f := &Flags{}

	// Helper to define string flag if not already defined
	defineStringFlag := func(name, value, usage string) *string {
		if fl := flag.Lookup(name); fl != nil {
			s, _ := fl.Value.(flag.Getter).Get().(string)
			return &s
		}
		return flag.String(name, value, usage)
	}
	defineBoolFlag := func(name string, value bool, usage string) *bool {
		if fl := flag.Lookup(name); fl != nil {
			b, _ := fl.Value.(flag.Getter).Get().(bool)
			return &b
		}
		return flag.Bool(name, value, usage)
	}
	defineIntFlag := func(name string, value int, usage string) *int {
		if fl := flag.Lookup(name); fl != nil {
			i, _ := fl.Value.(flag.Getter).Get().(int)
			return &i
		}
		return flag.Int(name, value, usage)
	}
	defineInt64Flag := func(name string, value int64, usage string) *int64 {
		if fl := flag.Lookup(name); fl != nil {
			i, _ := fl.Value.(flag.Getter).Get().(int64)
			return &i
		}
		return flag.Int64(name, value, usage)
	}
	defineUintFlag := func(name string, value uint, usage string) *uint {
		if fl := flag.Lookup(name); fl != nil {
			u64, _ := fl.Value.(flag.Getter).Get().(uint64)
			u := uint(u64)
			return &u
		}
		return flag.Uint(name, value, usage)
	}

	f.CPUProfile = defineStringFlag("cpuprofile", "", "write cpu profile to file")
	f.LogLevel = defineStringFlag("loglevel", "INFO", "log level: NONE, INFO, DEBUG, TRACE")
	f.LogFile = defineStringFlag("logfile", "", "write JSON logs to file (default: stdout)")
	f.Compress = defineBoolFlag("compress", false, "compress replies")
	f.TSIG = defineStringFlag("tsig", "", "use SHA256 hmac tsig: keyname:base64")
	f.SOReusePort = defineIntFlag("soreuseport", 0, "number of server instances to start with SO_REUSEPORT (0 to disable)")
	f.CPU = defineIntFlag("cpu", 0, "number of cpu to use")
	f.BaseDomain = defineStringFlag("basedomain", "_spf-stage.spffy.dev", "base domain for SPF macro queries")
	f.CacheLimit = defineInt64Flag("cachelimit", 1024*1024*1024, "cache memory limit in bytes (default: 1GB)")
	f.DNSServers = defineStringFlag("dnsservers", "", "comma-separated list of DNS servers to use for lookups (default: system resolver)")
	f.VoidLookupLimit = defineUintFlag("voidlookuplimit", 20, "maximum number of void DNS lookups allowed during SPF evaluation")
	f.CacheTTL = defineIntFlag("cachettl", 15, "cache TTL for SPF results in seconds")
	f.MaxConcurrent = defineIntFlag("maxconcurrent", 1000, "maximum concurrent SPF lookups")
	f.MetricsPort = defineIntFlag("metricsport", 8080, "port for metrics server")
	f.TCPAddr = defineStringFlag("tcpaddr", "[::]:8053", "TCP listen address (default: [::]:8053)")
	f.UDPAddr = defineStringFlag("udpaddr", ":8053", "UDP listen address (default: :8053)")
	f.RedisAddr = defineStringFlag("redisaddr", "localhost:6379", "Redis server address")
	f.RedisPassword = defineStringFlag("redispassword", "", "Redis password")
	f.RedisDB = defineIntFlag("redisdb", 0, "Redis database number")
	f.CacheType = defineStringFlag("cachetype", "inmemory", "type of cache to use: inmemory or redis")

	if !flag.Parsed() {
		flag.Usage = func() {
			flag.PrintDefaults()
			fmt.Println("\nEnvironment Variables:")
			fmt.Println("  All flags can also be set via environment variables with SPFFY_ prefix:")
			fmt.Println("  SPFFY_CPUPROFILE, SPFFY_LOGLEVEL, SPFFY_LOGFILE, SPFFY_COMPRESS,")
			fmt.Println("  SPFFY_TSIG, SPFFY_SOREUSEPORT, SPFFY_CPU, SPFFY_BASEDOMAIN,")
			fmt.Println("  SPFFY_CACHELIMIT, SPFFY_DNSSERVERS, SPFFY_VOIDLOOKUPLIMIT,")
			fmt.Println("  SPFFY_CACHETTL, SPFFY_MAXCONCURRENT, SPFFY_METRICSPORT,")
			fmt.Println("  SPFFY_TCPADDR, SPFFY_UDPADDR,")
			fmt.Println("  SPFFY_REDIS_ADDR, SPFFY_REDIS_PASSWORD, SPFFY_REDIS_DB, SPFFY_CACHE_TYPE")
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
	}
	LoadEnvConfig(f, flag.CommandLine) // Use default flag set for main application
	return f
}
