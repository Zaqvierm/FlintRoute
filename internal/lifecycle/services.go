package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type ManagedService struct {
	Service       string            `json:"service"`
	Instance      string            `json:"instance"`
	Component     string            `json:"component"`
	Owner         string            `json:"owner"`
	Active        bool              `json:"active"`
	PID           int               `json:"pid,omitempty"`
	StartTime     uint64            `json:"start_time_ticks,omitempty"`
	Executable    string            `json:"executable,omitempty"`
	ConfigPath    string            `json:"config_path,omitempty"`
	IdentityValid bool              `json:"identity_valid"`
	Checks        []string          `json:"checks,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type SystemService struct {
	Service string `json:"service"`
	Present bool   `json:"present"`
	Active  bool   `json:"active"`
	Note    string `json:"note,omitempty"`
}

type ServiceDiagnostics struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Managed     []ManagedService `json:"flintroute_managed"`
	System      []SystemService  `json:"system_services"`
}

type ServiceSpec struct {
	Component      string
	Service        string
	Instance       string
	Executable     string
	ConfigPath     string
	SystemServices []string
}

func DiagnoseServices(ctx context.Context, runner CommandRunner, inspector ProcessInspector, specs []ServiceSpec) ServiceDiagnostics {
	result := ServiceDiagnostics{GeneratedAt: time.Now().UTC()}
	if runner == nil {
		runner = ExecRunner{}
	}
	if inspector == nil {
		inspector = LinuxProcessInspector{}
	}
	seenSystem := map[string]bool{}
	for _, spec := range specs {
		managed := diagnoseManagedService(ctx, runner, inspector, spec)
		result.Managed = append(result.Managed, managed)
		for _, name := range spec.SystemServices {
			if seenSystem[name] {
				continue
			}
			seenSystem[name] = true
			result.System = append(result.System, diagnoseSystemService(ctx, runner, name))
		}
	}
	return result
}

func diagnoseManagedService(ctx context.Context, runner CommandRunner, inspector ProcessInspector, spec ServiceSpec) ManagedService {
	result := ManagedService{Service: spec.Service, Instance: spec.Instance, Component: spec.Component, Owner: string(OwnerProduction), ConfigPath: spec.ConfigPath}
	request, _ := json.Marshal(map[string]string{"name": spec.Service})
	raw, err := runner.Run(ctx, "ubus", "call", "service", "list", string(request))
	if err != nil {
		result.Checks = []string{"ubus service state unavailable"}
		return result
	}
	var payload map[string]struct {
		Instances map[string]struct {
			Running bool `json:"running"`
			PID     int  `json:"pid"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		result.Checks = []string{"ubus returned invalid JSON"}
		return result
	}
	service, ok := payload[spec.Service]
	if !ok {
		result.Checks = []string{"managed service not registered in procd"}
		return result
	}
	instance, ok := service.Instances[spec.Instance]
	if !ok {
		result.Checks = []string{"managed procd instance is absent"}
		return result
	}
	result.Active = instance.Running
	result.PID = instance.PID
	if !instance.Running || instance.PID <= 0 {
		result.Checks = []string{"procd instance is not running"}
		return result
	}
	actual, err := inspector.Inspect(instance.PID)
	if err != nil {
		result.Checks = []string{"PID from procd is not inspectable"}
		return result
	}
	result.StartTime = actual.StartTimeTicks
	result.Executable = actual.Executable
	exeMatches := spec.Executable == "" || cleanExecutable(actual.Executable) == cleanExecutable(spec.Executable)
	configMatches := spec.ConfigPath == "" || containsArg(actual.CommandLine, spec.ConfigPath)
	result.Checks = []string{fmt.Sprintf("procd PID %d is running", instance.PID)}
	if exeMatches {
		result.Checks = append(result.Checks, "executable matches")
	} else {
		result.Checks = append(result.Checks, "executable mismatch")
	}
	if configMatches {
		result.Checks = append(result.Checks, "config path matches")
	} else {
		result.Checks = append(result.Checks, "config path mismatch")
	}
	result.IdentityValid = exeMatches && configMatches && actual.StartTimeTicks > 0
	return result
}

func diagnoseSystemService(ctx context.Context, runner CommandRunner, name string) SystemService {
	path := "/etc/init.d/" + name
	result := SystemService{Service: name}
	if _, err := os.Stat(path); err == nil {
		result.Present = true
	} else if !errors.Is(err, os.ErrNotExist) {
		result.Note = "service presence could not be verified"
		return result
	} else {
		result.Note = "service is not installed"
		return result
	}
	_, err := runner.Run(ctx, path, "status")
	result.Active = err == nil
	if !result.Active {
		result.Note = "inactive is valid when FlintRoute owns a separate procd instance"
	}
	return result
}

func cleanExecutable(value string) string {
	return strings.TrimSuffix(value, " (deleted)")
}
