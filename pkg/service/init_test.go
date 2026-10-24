package service_test

import (
	"context"
	tlsX509 "crypto/x509"
	tlsErrors "errors"
	tlsIO "io"
	tlsLog "log"
	tlsHTTP "net/http"
	tlsServer "net/http/httptest"
	tlsAtomic "sync/atomic"
	"testing"
	"time"

	tlsYAML "gopkg.in/yaml.v2"

	"github.com/free5gc/bsf/pkg/factory"
	"github.com/free5gc/bsf/pkg/service"
	tlsOpenAPI "github.com/free5gc/openapi"
	tlsNFM "github.com/free5gc/openapi/nrf/NFMgmt"
)

func TestNewApp(t *testing.T) {
	cfg := &factory.Config{
		Configuration: &factory.Configuration{
			Sbi: &factory.Sbi{
				Scheme:      "http",
				BindingIPv4: "127.0.0.1",
				Port:        8099,
			},
		},
		Logger: &factory.Logger{
			Enable:       false,
			Level:        "info",
			ReportCaller: false,
		},
	}

	ctx := context.Background()
	app, err := service.NewApp(ctx, cfg, "")
	if err != nil {
		t.Fatalf("Failed to create app: %v", err)
	}

	if app == nil {
		t.Fatal("App is nil")
	}

	if app.Config() != cfg {
		t.Error("Config mismatch")
	}

	if app.Context() == nil {
		t.Error("BSF Context is nil")
	}

	if app.Consumer() == nil {
		t.Error("Consumer is nil")
	}

	if app.Processor() == nil {
		t.Error("Processor is nil")
	}

	t.Log("NewApp successfully created BSF app with all components")
}

func TestAppStartTerminate(t *testing.T) {
	cfg := &factory.Config{
		Info: &factory.Info{
			Version:     "1.0.2",
			Description: "BSF test configuration",
		},
		Configuration: &factory.Configuration{
			Sbi: &factory.Sbi{
				Scheme:      "http",
				BindingIPv4: "127.0.0.1",
				Port:        8100,
			},
		},
		Logger: &factory.Logger{
			Enable:       false,
			Level:        "info",
			ReportCaller: false,
		},
	}
	factory.BsfConfig = cfg

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cancel is called on all paths

	app, err := service.NewApp(ctx, cfg, "")
	if err != nil {
		t.Fatalf("Failed to create app: %v", err)
	}

	// Start app in goroutine
	startDone := make(chan struct{})
	go func() {
		app.Start()
		close(startDone)
	}()

	// Give server time to start
	time.Sleep(500 * time.Millisecond)

	// Trigger shutdown via Terminate (which cancels context)
	startTime := time.Now()
	app.Terminate()

	// Wait for Start to return with longer timeout
	select {
	case <-startDone:
		duration := time.Since(startTime)
		t.Logf("App stopped in %v after Terminate() call", duration)
		if duration > 15*time.Second {
			t.Errorf("App took too long to stop: %v", duration)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("App did not stop within 20 seconds")
	}
}

func TestAppInterface(t *testing.T) {
	cfg := &factory.Config{
		Configuration: &factory.Configuration{
			Sbi: &factory.Sbi{
				Scheme:      "http",
				BindingIPv4: "127.0.0.1",
				Port:        8101,
			},
		},
		Logger: &factory.Logger{
			Enable:       false,
			Level:        "info",
			ReportCaller: false,
		},
	}

	ctx := context.Background()
	app, err := service.NewApp(ctx, cfg, "")
	if err != nil {
		t.Fatalf("Failed to create app: %v", err)
	}

	// Test that BsfApp implements BsfAppInterface
	var _ service.BsfAppInterface = app

	// Test log functions don't panic
	app.SetLogEnable(false)
	app.SetLogLevel("debug")
	app.SetReportCaller(false)

	t.Log("App successfully implements all interface methods")
}

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		if err := tlsOpenAPI.ConfigureHTTP2Clients(
			tlsOpenAPI.TransportReadIdleTimeout, tlsOpenAPI.TransportPingTimeout, false,
		); err != nil {
			t.Errorf("restore HTTP clients: %v", err)
		}
	})
	var requests tlsAtomic.Int32
	server := tlsServer.NewUnstartedServer(tlsHTTP.HandlerFunc(func(w tlsHTTP.ResponseWriter, r *tlsHTTP.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := tlsIO.WriteString(w, `{}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = tlsLog.New(tlsIO.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    tls:\n      verify: " + value + "\n"
			}
			var cfg factory.Config
			if err := tlsYAML.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := tlsOpenAPI.ConfigureHTTP2Clients(
				cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify(),
			); err != nil {
				t.Fatal(err)
			}
			apiCfg := tlsNFM.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := tlsNFM.NewAPIClient(apiCfg)
			req := &tlsNFM.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(context.Background(), req)
			if value == "true" {
				var unknown tlsX509.UnknownAuthorityError
				if !tlsErrors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
