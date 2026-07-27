package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	responses map[string][]byte
	errors    map[string]error
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	return f.responses[key], f.errors[key]
}

func TestManagedServiceOwnerUsesProcdAndFullProcessIdentity(t *testing.T) {
	request := `{"name":"router-policy-xray"}`
	runner := fakeRunner{responses: map[string][]byte{
		"ubus call service list " + request: []byte(`{"router-policy-xray":{"instances":{"router-policy-xray":{"running":true,"pid":73}}}}`),
	}, errors: map[string]error{}}
	inspector := &fakeInspector{identities: map[int]ProcessIdentity{73: {
		PID: 73, StartTimeTicks: 12345, Executable: "/usr/bin/xray", CommandLine: []string{"/usr/bin/xray", "run", "-config", "/etc/router-policy/xray/active.json"},
	}}}
	report := DiagnoseServices(context.Background(), runner, inspector, []ServiceSpec{{
		Component: "xray", Service: "router-policy-xray", Instance: "router-policy-xray", Executable: "/usr/bin/xray", ConfigPath: "/etc/router-policy/xray/active.json",
	}})
	if len(report.Managed) != 1 || !report.Managed[0].Active || !report.Managed[0].IdentityValid || report.Managed[0].Owner != "production" {
		t.Fatalf("managed Xray identity not proved: %+v", report)
	}
}

func TestManagedServiceRejectsConfigMismatch(t *testing.T) {
	request := `{"name":"router-policy-zapret"}`
	runner := fakeRunner{responses: map[string][]byte{
		"ubus call service list " + request: []byte(`{"router-policy-zapret":{"instances":{"router-policy-zapret":{"running":true,"pid":74}}}}`),
	}, errors: map[string]error{}}
	inspector := &fakeInspector{identities: map[int]ProcessIdentity{74: {
		PID: 74, StartTimeTicks: 12346, Executable: "/usr/bin/nfqws", CommandLine: []string{"/usr/bin/nfqws", "@/tmp/foreign.conf"},
	}}}
	report := DiagnoseServices(context.Background(), runner, inspector, []ServiceSpec{{
		Component: "zapret", Service: "router-policy-zapret", Instance: "router-policy-zapret", Executable: "/usr/bin/nfqws", ConfigPath: "/etc/router-policy/zapret/nfqws.conf",
	}})
	if report.Managed[0].IdentityValid {
		t.Fatalf("foreign config was accepted: %+v", report.Managed[0])
	}
	if !errors.Is(runner.errors["missing"], nil) {
		t.Fatal("unreachable")
	}
}
