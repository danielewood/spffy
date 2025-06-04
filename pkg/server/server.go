package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync" // Required for HTTPServer.mu if we add it for config updates.

	"github.com/danielewood/spffy/pkg/cache"
	"github.com/danielewood/spffy/pkg/config"
	"github.com/danielewood/spffy/pkg/logging"
	"github.com/danielewood/spffy/pkg/resolver"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HTTPServer holds dependencies for the HTTP server.
type HTTPServer struct {
	Logger       logging.LoggerInterface
	LogBuffer    *logging.LogBuffer // Direct access to LogBuffer for /logs
	Config       *config.Flags      // Direct access to global config flags
	Cache        cache.CacheInterface
	ResolverPool **resolver.ResolverPool // Pointer to the pointer in main.go
	SPFSemaphore *chan struct{}          // Pointer to the channel in main.go
	mu           sync.Mutex              // To protect dynamic updates to shared resources via /settings
}

// NewHTTPServer creates a new HTTPServer.
func NewHTTPServer(
	logger logging.LoggerInterface,
	logBuffer *logging.LogBuffer,
	cfg *config.Flags,
	cache cache.CacheInterface,
	resolverPool **resolver.ResolverPool,
	spfSemaphore *chan struct{},
) *HTTPServer {
	return &HTTPServer{
		Logger:       logger,
		LogBuffer:    logBuffer,
		Config:       cfg,
		Cache:        cache,
		ResolverPool: resolverPool,
		SPFSemaphore: spfSemaphore,
	}
}

// Start launches the HTTP server with metrics, logs, and settings endpoints.
func (s *HTTPServer) Start() {
	// Note: Prometheus metrics are typically registered with prometheus.DefaultRegisterer
	// by their owning packages (e.g., cache, dns modules).
	// promhttp.Handler() serves metrics from the DefaultRegisterer.
	// So, this server doesn't need to explicitly register metrics owned by other packages.
	// If this server itself owned specific metrics, they would be registered here.

	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stream") == "true" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")

			clientChan := s.LogBuffer.RegisterClient()
			defer s.LogBuffer.UnregisterClient(clientChan)

			// Send existing logs first
			for _, logEntry := range s.LogBuffer.GetAll() {
				fmt.Fprintf(w, "data: %s\n\n", logEntry)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			// Stream new logs
			for logEntry := range clientChan {
				fmt.Fprintf(w, "data: %s\n\n", logEntry)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		} else {
			// Use the originalLogViewerHTML constant
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, originalLogViewerHTML)
		}
	})

	http.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			currentSettings := config.Settings{ // Assuming config.Settings is the DTO
				CPUProfile:      *s.Config.CPUProfile,
				LogLevel:        *s.Config.LogLevel,
				LogFile:         *s.Config.LogFile,
				Compress:        *s.Config.Compress,
				TSIG:            *s.Config.TSIG,
				SOReusePort:     *s.Config.SOReusePort,
				CPU:             *s.Config.CPU,
				BaseDomain:      *s.Config.BaseDomain,
				CacheLimit:      *s.Config.CacheLimit,
				DNSServers:      *s.Config.DNSServers,
				VoidLookupLimit: *s.Config.VoidLookupLimit,
				CacheTTL:        *s.Config.CacheTTL,
				MaxConcurrent:   *s.Config.MaxConcurrent,
				MetricsPort:     *s.Config.MetricsPort,
				TCPAddr:         *s.Config.TCPAddr,
				UDPAddr:         *s.Config.UDPAddr,
			}
			if err := enc.Encode(currentSettings); err != nil {
				http.Error(w, "Failed to encode settings", http.StatusInternalServerError)
			}

		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			var newSettings config.Settings
			if err := json.Unmarshal(body, &newSettings); err != nil {
				http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Basic Validations (could be more extensive)
			switch strings.ToUpper(newSettings.LogLevel) {
			case "NONE", "INFO", "DEBUG", "TRACE": // Valid levels
			default:
				http.Error(w, "Invalid loglevel: must be NONE, INFO, DEBUG, or TRACE", http.StatusBadRequest)
				return
			}
			if newSettings.CacheTTL < 0 {
				http.Error(w, "CacheTTL must be non-negative", http.StatusBadRequest)
				return
			}
			// Add other validations as in original main.go...

			restartRequiredMessages := []string{}
			if newSettings.SOReusePort != *s.Config.SOReusePort ||
				newSettings.MetricsPort != *s.Config.MetricsPort ||
				newSettings.CPU != *s.Config.CPU ||
				newSettings.TCPAddr != *s.Config.TCPAddr || // Assuming direct change needs restart
				newSettings.UDPAddr != *s.Config.UDPAddr { // Assuming direct change needs restart
				restartRequiredMessages = append(restartRequiredMessages, "Server port/CPU changes require program restart.")
			}

			// Update config.Flags (pointers ensure this updates the shared instance from main)
			*s.Config.LogLevel = newSettings.LogLevel
			*s.Config.LogFile = newSettings.LogFile // Logger needs reconfigure
			*s.Config.CacheLimit = newSettings.CacheLimit
			*s.Config.CacheTTL = newSettings.CacheTTL
			*s.Config.DNSServers = newSettings.DNSServers
			*s.Config.MaxConcurrent = newSettings.MaxConcurrent
			// Update other non-restart flags
			*s.Config.CPUProfile = newSettings.CPUProfile
			*s.Config.Compress = newSettings.Compress
			*s.Config.TSIG = newSettings.TSIG
			*s.Config.BaseDomain = newSettings.BaseDomain
			*s.Config.VoidLookupLimit = newSettings.VoidLookupLimit

			// Apply changes to components
			s.Logger.Reconfigure(*s.Config.LogLevel, *s.Config.LogFile, s.LogBuffer) // Assuming LogBuffer doesn't change
			s.Cache.SetLimit(*s.Config.CacheLimit)
			s.Cache.SetTTL(*s.Config.CacheTTL)

			// Update ResolverPool by creating a new one and assigning to the dereferenced pointer
			if s.ResolverPool != nil && *s.ResolverPool != nil { // Check if main passed a valid pointer
				**s.ResolverPool = *resolver.NewResolverPool(*s.Config.DNSServers)
			}

			// Update SPFSemaphore by creating a new channel and assigning to the dereferenced pointer
			if s.SPFSemaphore != nil && *s.SPFSemaphore != nil { // Check if main passed a valid pointer
				// Note: This changes the channel. Goroutines waiting on the old channel
				// might behave unexpectedly if not handled. A more robust solution might involve
				// a wrapper around the semaphore that allows dynamic capacity changes,
				// or signaling existing workers to stop and starting new ones.
				// For now, direct replacement:
				newSemaphore := make(chan struct{}, *s.Config.MaxConcurrent)
				*s.SPFSemaphore = newSemaphore
			}

			s.Logger.Info(map[string]interface{}{"message": "Settings updated", "new_settings": newSettings})

			response := map[string]interface{}{"status": "updated", "message": "Settings updated successfully."}
			if len(restartRequiredMessages) > 0 {
				response["status"] = "updated_with_restart_required"
				response["message"] = "Some settings updated, but restart required for: " + strings.Join(restartRequiredMessages, ", ")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	addr := fmt.Sprintf(":%d", *s.Config.MetricsPort)
	s.Logger.Info(map[string]interface{}{"message": fmt.Sprintf("Metrics, logs, and settings server starting on port %d", *s.Config.MetricsPort)})

	// Start LogBuffer broadcast only if it's not nil (it's always initialized in main)
	if s.LogBuffer != nil {
		go s.LogBuffer.Broadcast()
	}

	if err := http.ListenAndServe(addr, nil); err != nil {
		s.Logger.Info(map[string]interface{}{"error": fmt.Sprintf("Failed to start metrics server: %s", err.Error())})
	}
}

// The original HTML for log viewing from main.go (for reference, will use this one)
const originalLogViewerHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>SPFFY Logs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/monokai-sublime.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>hljs.highlightAll();</script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; }
        #logs { max-height: calc(100vh - 80px); overflow-y: auto; }
        .log-entry { border-bottom: 1px solid #4a5568; }
        pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
        .toggle-button { position: fixed; top: 10px; right: 10px; }
    </style>
</head>
<body class="p-4">
    <button id="toggleFormat" class="toggle-button bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded">Toggle Format</button>
    <div id="logs" class="bg-gray-800 rounded-lg p-4"></div>
    <script>
        const logs = document.getElementById('logs');
        const toggleButton = document.getElementById('toggleFormat');
        let isFormatted = false;
        let source = null;

        function connectSource() {
            if (source) {
                source.close();
            }
            source = new EventSource('/logs?stream=true');
            source.onmessage = function(event) {
                if (!event.data.trim()) return;
                addLog(event.data);
            };
            source.onerror = function() {
                source.close();
                const div = document.createElement('div');
                div.className = 'log-entry p-2 text-red-400';
                div.textContent = 'Connection lost. Please refresh to reconnect.';
                logs.appendChild(div);
            };
        }

        function formatLog(log) {
            try {
                const parsed = JSON.parse(log);
                return isFormatted ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed);
            } catch (e) {
                return log;
            }
        }

        function addLog(log) {
            const div = document.createElement('div');
            div.className = 'log-entry p-2';
            const pre = document.createElement('pre');
            pre.innerHTML = hljs.highlight(formatLog(log), { language: 'json' }).value;
            div.appendChild(pre);
            logs.appendChild(div);
            logs.scrollTop = logs.scrollHeight;
        }

        toggleButton.addEventListener('click', () => {
            isFormatted = !isFormatted;
            logs.innerHTML = ''; // Clear previous logs before re-streaming or re-adding
            // When toggling, should ideally re-fetch initial logs if EventSource doesn't provide them all again.
            // For simplicity, new stream will just show new logs after toggle.
            // Or, could try to re-add from a client-side buffer if we stored them.
            // The original version did not explicitly re-fetch or re-add here.
            // It just set the format and new logs would use it.
            // Let's stick to simple: connectSource will fetch new logs.
            toggleButton.textContent = isFormatted ? 'Raw JSON' : 'Formatted JSON';
            connectSource();
        });
        connectSource();
    </script>
</body>
</html>
`

// I will replace the HandleFunc for /logs to use this constant.
// And remove the JS line `s.LogBuffer.GetAll().forEach(log => addLog(log));` as it's incorrect.
// The original JS in main.go was fine.
