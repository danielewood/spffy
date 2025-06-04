package config

import (
	"bytes"
	"flag"
	"os"
	"testing"
)

// MockLogger captures log output for testing PrintConfig
type MockLogger struct {
	Messages []map[string]interface{}
}

func (m *MockLogger) Log(msg map[string]interface{}) {
	m.Messages = append(m.Messages, msg)
}

// newTestFlags creates a fully initialized Flags struct with a given flag set
func newTestFlags(fs *flag.FlagSet) *Flags {
	return &Flags{
		CPUProfile:      fs.String("cpuprofile", "", ""),
		LogLevel:        fs.String("loglevel", "INFO", ""),
		LogFile:         fs.String("logfile", "", ""),
		Compress:        fs.Bool("compress", false, ""),
		TSIG:            fs.String("tsig", "", ""),
		SOReusePort:     fs.Int("soreuseport", 0, ""),
		CPU:             fs.Int("cpu", 0, ""),
		BaseDomain:      fs.String("basedomain", "_spf-stage.spffy.dev", ""),
		CacheLimit:      fs.Int64("cachelimit", 1024*1024*1024, ""),
		DNSServers:      fs.String("dnsservers", "", ""),
		VoidLookupLimit: fs.Uint("voidlookuplimit", 20, ""),
		CacheTTL:        fs.Int("cachettl", 15, ""),
		MaxConcurrent:   fs.Int("maxconcurrent", 1000, ""),
		MetricsPort:     fs.Int("metricsport", 8080, ""),
		TCPAddr:         fs.String("tcpaddr", "[::]:8053", ""),
		UDPAddr:         fs.String("udpaddr", ":8053", ""),
		RedisAddr:       fs.String("redisaddr", "localhost:6379", ""),
		RedisPassword:   fs.String("redispassword", "", ""),
		RedisDB:         fs.Int("redisdb", 0, ""),
		CacheType:       fs.String("cachetype", "inmemory", ""),
	}
}

// TestGetInitialSettings tests the GetInitialSettings function
func TestGetInitialSettings(t *testing.T) {
	// Create a new flag set to isolate tests from the default flag set
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	// Reset flag.CommandLine to avoid conflicts with other tests
	origCommandLine := flag.CommandLine
	flag.CommandLine = fs
	defer func() { flag.CommandLine = origCommandLine }()

	// Test default values
	t.Run("DefaultValues", func(t *testing.T) {
		f := GetInitialSettings()
		if *f.LogLevel != "INFO" {
			t.Errorf("LogLevel = %q, want %q", *f.LogLevel, "INFO")
		}
		if *f.CacheLimit != 1024*1024*1024 {
			t.Errorf("CacheLimit = %d, want %d", *f.CacheLimit, 1024*1024*1024)
		}
		if *f.BaseDomain != "_spf-stage.spffy.dev" {
			t.Errorf("BaseDomain = %q, want %q", *f.BaseDomain, "_spf-stage.spffy.dev")
		}
		if *f.Compress != false {
			t.Errorf("Compress = %v, want %v", *f.Compress, false)
		}
		if *f.MetricsPort != 8080 {
			t.Errorf("MetricsPort = %d, want %d", *f.MetricsPort, 8080)
		}
	})

	// Test with command-line flags
	t.Run("CommandLineFlags", func(t *testing.T) {
		fs = flag.NewFlagSet("test", flag.ContinueOnError)
		flag.CommandLine = fs
		os.Args = []string{"cmd", "-loglevel=DEBUG", "-cachelimit=2048", "-basedomain=test.com"}
		f := GetInitialSettings()
		if *f.LogLevel != "DEBUG" {
			t.Errorf("LogLevel = %q, want %q", *f.LogLevel, "DEBUG")
		}
		if *f.CacheLimit != 2048 {
			t.Errorf("CacheLimit = %d, want %d", *f.CacheLimit, 2048)
		}
		if *f.BaseDomain != "test.com" {
			t.Errorf("BaseDomain = %q, want %q", *f.BaseDomain, "test.com")
		}
	})
}

// TestLoadEnvConfig tests environment variable loading
func TestLoadEnvConfig(t *testing.T) {
	// Helper to reset environment variables
	resetEnv := func() {
		os.Unsetenv("SPFFY_CPUPROFILE")
		os.Unsetenv("SPFFY_LOGLEVEL")
		os.Unsetenv("SPFFY_LOGFILE")
		os.Unsetenv("SPFFY_COMPRESS")
		os.Unsetenv("SPFFY_TSIG")
		os.Unsetenv("SPFFY_SOREUSEPORT")
		os.Unsetenv("SPFFY_CPU")
		os.Unsetenv("SPFFY_BASEDOMAIN")
		os.Unsetenv("SPFFY_CACHELIMIT")
		os.Unsetenv("SPFFY_DNSSERVERS")
		os.Unsetenv("SPFFY_VOIDLOOKUPLIMIT")
		os.Unsetenv("SPFFY_CACHETTL")
		os.Unsetenv("SPFFY_MAXCONCURRENT")
		os.Unsetenv("SPFFY_METRICSPORT")
		os.Unsetenv("SPFFY_TCPADDR")
		os.Unsetenv("SPFFY_UDPADDR")
		os.Unsetenv("SPFFY_REDIS_ADDR")
		os.Unsetenv("SPFFY_REDIS_PASSWORD")
		os.Unsetenv("SPFFY_REDIS_DB")
		os.Unsetenv("SPFFY_CACHE_TYPE")
	}
	defer resetEnv()

	t.Run("NoEnvVars", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		f := newTestFlags(fs)
		resetEnv()
		LoadEnvConfig(f, fs) // Pass the flag set
		if *f.LogLevel != "INFO" {
			t.Errorf("LogLevel = %q, want %q", *f.LogLevel, "INFO")
		}
		if *f.CacheLimit != 1024*1024*1024 {
			t.Errorf("CacheLimit = %d, want %d", *f.CacheLimit, 1024*1024*1024)
		}
	})

	t.Run("EnvVarsOverride", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		f := newTestFlags(fs)
		resetEnv()
		os.Setenv("SPFFY_LOGLEVEL", "DEBUG")
		os.Setenv("SPFFY_CACHELIMIT", "2048")
		os.Setenv("SPFFY_COMPRESS", "true")
		os.Setenv("SPFFY_VOIDLOOKUPLIMIT", "30")
		os.Setenv("SPFFY_METRICSPORT", "9090")
		os.Setenv("SPFFY_REDIS_ADDR", "redis:6379")
		LoadEnvConfig(f, fs)
		if *f.LogLevel != "DEBUG" {
			t.Errorf("LogLevel = %q, want %q", *f.LogLevel, "DEBUG")
		}
		if *f.CacheLimit != 2048 {
			t.Errorf("CacheLimit = %d, want %d", *f.CacheLimit, 2048)
		}
		if *f.Compress != true {
			t.Errorf("Compress = %v, want %v", *f.Compress, true)
		}
		if *f.VoidLookupLimit != 30 {
			t.Errorf("VoidLookupLimit = %d, want %d", *f.VoidLookupLimit, 30)
		}
		if *f.MetricsPort != 9090 {
			t.Errorf("MetricsPort = %d, want %d", *f.MetricsPort, 9090)
		}
		if *f.RedisAddr != "redis:6379" {
			t.Errorf("RedisAddr = %q, want %q", *f.RedisAddr, "redis:6379")
		}
	})

	t.Run("NoOverrideIfFlagSet", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		f := newTestFlags(fs)
		resetEnv()
		os.Setenv("SPFFY_LOGLEVEL", "TRACE")
		fs.Parse([]string{"-loglevel=DEBUG"}) // Simulate flag being set
		LoadEnvConfig(f, fs)
		if *f.LogLevel != "DEBUG" {
			t.Errorf("LogLevel = %q, want %q (flag should take precedence)", *f.LogLevel, "DEBUG")
		}
	})

	t.Run("InvalidEnvVars", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		f := newTestFlags(fs)
		resetEnv()
		os.Setenv("SPFFY_CACHELIMIT", "invalid")
		os.Setenv("SPFFY_COMPRESS", "notabool")
		LoadEnvConfig(f, fs)
		if *f.CacheLimit != 1024*1024*1024 {
			t.Errorf("CacheLimit = %d, want %d (invalid env var should be ignored)", *f.CacheLimit, 1024*1024*1024)
		}
		if *f.Compress != false {
			t.Errorf("Compress = %v, want %v (invalid env var should be ignored)", *f.Compress, false)
		}
	})
}

// TestPrintConfig tests the PrintConfig function
func TestPrintConfig(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := newTestFlags(fs)
	*f.LogLevel = "DEBUG"
	*f.CacheLimit = 1024 * 1024 * 1024 // Use default to match GetInitialSettings
	*f.BaseDomain = "test.com"
	*f.MetricsPort = 9090
	*f.Compress = true

	mockLogger := &MockLogger{}
	PrintConfig(f, mockLogger.Log)

	if len(mockLogger.Messages) != 1 {
		t.Fatalf("Expected 1 log message, got %d", len(mockLogger.Messages))
	}

	msg := mockLogger.Messages[0]
	if msg["message"] != "Configuration" {
		t.Errorf("Log message = %q, want %q", msg["message"], "Configuration")
	}

	configMap, ok := msg["config"].(map[string]interface{})
	if !ok {
		t.Fatalf("Config field is not a map: %v", msg["config"])
	}

	if configMap["SPFFY_LOGLEVEL"] != "DEBUG" {
		t.Errorf("Config SPFFY_LOGLEVEL = %q, want %q", configMap["SPFFY_LOGLEVEL"], "DEBUG")
	}

	expectedCacheLimit := float64(1024 * 1024 * 1024)
	var actual float64
	switch v := configMap["SPFFY_CACHELIMIT"].(type) {
	case float64:
		actual = v
	case int64:
		actual = float64(v)
	case int:
		actual = float64(v)
	default:
		t.Fatalf("Unexpected type for SPFFY_CACHELIMIT: %T", v)
	}
	if actual != expectedCacheLimit {
		t.Errorf("Config SPFFY_CACHELIMIT = %f, want %f", actual, expectedCacheLimit)
	}

	if configMap["SPFFY_BASEDOMAIN"] != "test.com" {
		t.Errorf("Config SPFFY_BASEDOMAIN = %q, want %q", configMap["SPFFY_BASEDOMAIN"], "test.com")
	}
}

// TestEnvHelpers tests the environment variable parsing helper functions
func TestEnvHelpers(t *testing.T) {
	// Helper to reset environment variable
	resetEnv := func(key string) { os.Unsetenv(key) }
	defer resetEnv("TEST_ENV")

	t.Run("envString", func(t *testing.T) {
		resetEnv("TEST_ENV")
		if val := envString("TEST_ENV", "default"); val != "default" {
			t.Errorf("envString = %q, want %q", val, "default")
		}
		os.Setenv("TEST_ENV", "value")
		if val := envString("TEST_ENV", "default"); val != "value" {
			t.Errorf("envString = %q, want %q", val, "value")
		}
	})

	t.Run("envBool", func(t *testing.T) {
		resetEnv("TEST_ENV")
		if val := envBool("TEST_ENV", false); val != false {
			t.Errorf("envBool = %v, want %v", val, false)
		}
		os.Setenv("TEST_ENV", "true")
		if val := envBool("TEST_ENV", false); val != true {
			t.Errorf("envBool = %v, want %v", val, true)
		}
		os.Setenv("TEST_ENV", "invalid")
		if val := envBool("TEST_ENV", false); val != false {
			t.Errorf("envBool = %v, want %v (invalid bool should return default)", val, false)
		}
	})

	t.Run("envInt", func(t *testing.T) {
		resetEnv("TEST_ENV")
		if val := envInt("TEST_ENV", 42); val != 42 {
			t.Errorf("envInt = %d, want %d", val, 42)
		}
		os.Setenv("TEST_ENV", "100")
		if val := envInt("TEST_ENV", 42); val != 100 {
			t.Errorf("envInt = %d, want %d", val, 100)
		}
		os.Setenv("TEST_ENV", "invalid")
		if val := envInt("TEST_ENV", 42); val != 42 {
			t.Errorf("envInt = %d, want %d (invalid int should return default)", val, 42)
		}
	})

	t.Run("envInt64", func(t *testing.T) {
		resetEnv("TEST_ENV")
		if val := envInt64("TEST_ENV", 1024); val != 1024 {
			t.Errorf("envInt64 = %d, want %d", val, 1024)
		}
		os.Setenv("TEST_ENV", "2048")
		if val := envInt64("TEST_ENV", 1024); val != 2048 {
			t.Errorf("envInt64 = %d, want %d", val, 2048)
		}
		os.Setenv("TEST_ENV", "invalid")
		if val := envInt64("TEST_ENV", 1024); val != 1024 {
			t.Errorf("envInt64 = %d, want %d (invalid int64 should return default)", val, 1024)
		}
	})

	t.Run("envUint", func(t *testing.T) {
		resetEnv("TEST_ENV")
		if val := envUint("TEST_ENV", 20); val != 20 {
			t.Errorf("envUint = %d, want %d", val, 20)
		}
		os.Setenv("TEST_ENV", "30")
		if val := envUint("TEST_ENV", 20); val != 30 {
			t.Errorf("envUint = %d, want %d", val, 30)
		}
		os.Setenv("TEST_ENV", "invalid")
		if val := envUint("TEST_ENV", 20); val != 20 {
			t.Errorf("envUint = %d, want %d (invalid uint should return default)", val, 20)
		}
		os.Setenv("TEST_ENV", "-1")
		if val := envUint("TEST_ENV", 20); val != 20 {
			t.Errorf("envUint = %d, want %d (negative uint should return default)", val, 20)
		}
	})
}
