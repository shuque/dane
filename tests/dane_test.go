package tests

import (
	"testing"

	"github.com/shuque/dane"
)

func TestNewConfig(t *testing.T) {
	hostname := "example.com"
	ip := "192.0.2.1"
	port := 443

	config := dane.NewConfig(hostname, ip, port)
	if config == nil {
		t.Fatal("NewConfig returned nil")
	}

	if config.Server == nil {
		t.Fatal("Server is nil")
	}

	if config.Server.Name != hostname {
		t.Errorf("Expected hostname %s, got %s", hostname, config.Server.Name)
	}

	if config.Server.Port != port {
		t.Errorf("Expected port %d, got %d", port, config.Server.Port)
	}

	if !config.DANE {
		t.Error("DANE authentication should be enabled by default")
	}

	if !config.PKIX {
		t.Error("PKIX fallback should be enabled by default")
	}
}

func TestGetResolver(t *testing.T) {
	resolver, err := dane.GetResolver("")
	if err != nil {
		t.Fatalf("GetResolver failed: %v", err)
	}
	if resolver == nil {
		t.Fatal("GetResolver returned nil resolver")
	}
}

func TestNoPKIXfallback(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	config.NoPKIXfallback()

	if config.PKIX {
		t.Error("NoPKIXfallback did not disable PKIX fallback")
	}
}

func TestDaneEEnameOption(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	config.DaneEEname = true

	if !config.DaneEEname {
		t.Error("DaneEEname option not set correctly")
	}
}

func TestSMTPAnyModeOption(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	config.SMTPAnyMode = true

	if !config.SMTPAnyMode {
		t.Error("SMTPAnyMode option not set correctly")
	}
}

func TestDiagMode(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	config.SetDiagMode(true)

	if !config.DiagMode {
		t.Error("DiagMode option not set correctly")
	}
}

func TestSetALPN(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	alpnStrings := []string{"h2", "http/1.1"}
	config.SetALPN(alpnStrings)

	if len(config.ALPN) != len(alpnStrings) {
		t.Errorf("Expected %d ALPN strings, got %d", len(alpnStrings), len(config.ALPN))
	}

	for i, s := range alpnStrings {
		if config.ALPN[i] != s {
			t.Errorf("Expected ALPN string %s at index %d, got %s", s, i, config.ALPN[i])
		}
	}
}

func TestSetAppName(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	appname := "smtp"
	config.SetAppName(appname)

	if config.Appname != appname {
		t.Errorf("Expected appname %s, got %s", appname, config.Appname)
	}
}

func TestSetServiceName(t *testing.T) {
	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	servicename := "submission"
	config.SetServiceName(servicename)

	if config.Servicename != servicename {
		t.Errorf("Expected servicename %s, got %s", servicename, config.Servicename)
	}
}

func TestTLSAInfo(t *testing.T) {
	// Create a test TLSA record
	tlsa := &dane.TLSAinfo{
		Qname: "_443._tcp.example.com",
		Rdata: []*dane.TLSArdata{
			{
				Usage:    dane.DaneEE,
				Selector: 0,
				Mtype:    1,
				Data:     "0123456789abcdef",
			},
		},
	}

	config := dane.NewConfig("example.com", "192.0.2.1", 443)
	config.SetTLSA(tlsa)

	if config.TLSA == nil {
		t.Fatal("TLSA info is nil")
	}

	if config.TLSA.Qname != tlsa.Qname {
		t.Errorf("Expected Qname %s, got %s", tlsa.Qname, config.TLSA.Qname)
	}

	if len(config.TLSA.Rdata) != len(tlsa.Rdata) {
		t.Errorf("Expected %d TLSA records, got %d", len(tlsa.Rdata), len(config.TLSA.Rdata))
	}

	if config.TLSA.Rdata[0].Usage != tlsa.Rdata[0].Usage {
		t.Errorf("Expected Usage %d, got %d", tlsa.Rdata[0].Usage, config.TLSA.Rdata[0].Usage)
	}
}

func TestTLSAUncheck(t *testing.T) {
	tlsa := &dane.TLSAinfo{
		Qname: "_443._tcp.example.com",
		Rdata: []*dane.TLSArdata{
			{
				Usage:    dane.DaneEE,
				Selector: 0,
				Mtype:    1,
				Data:     "0123456789abcdef",
				Checked:  true,
				Ok:       true,
				Message:  "test message",
			},
		},
	}

	tlsa.Uncheck()

	if tlsa.Rdata[0].Checked {
		t.Error("TLSA record should be unchecked")
	}

	if tlsa.Rdata[0].Ok {
		t.Error("TLSA record should not be marked as OK")
	}

	if tlsa.Rdata[0].Message != "" {
		t.Error("TLSA record message should be cleared")
	}
}
