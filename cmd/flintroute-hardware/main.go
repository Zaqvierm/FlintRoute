package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"router-policy/internal/hardwarevalidation"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: flintroute-hardware baseline|smart-dns|matrix|recursion|load|finalize [flags]")
	}
	paths := hardwarevalidation.DefaultPaths()
	switch args[0] {
	case "baseline":
		fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		commit := fs.String("commit", "", "source commit SHA")
		buildSHA := fs.String("build-sha256", "", "installed router-policy SHA-256")
		recoverySHA := fs.String("recovery-sha256", "", "external recovery bundle SHA-256")
		config := fs.String("config", paths.Config, "active FlintRoute config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("baseline received unexpected arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		paths.Config = *config
		runner := hardwarevalidation.ExecRunner{Env: append(os.Environ(), "ROUTER_POLICY_CONFIG="+*config)}
		harness := hardwarevalidation.Harness{Runner: runner, Paths: paths}
		result, err := harness.Baseline(context.Background(), hardwarevalidation.BaselineOptions{RunDir: *runDir, Commit: *commit, BuildSHA256: *buildSHA, RecoverySHA256: *recoverySHA})
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "matrix":
		fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		cases := fs.String("cases", "", "matrix case file")
		config := fs.String("config", paths.Config, "active FlintRoute config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *cases == "" || fs.NArg() != 0 {
			return errors.New("matrix requires --cases and no positional arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		paths.Config = *config
		runner := hardwarevalidation.ExecRunner{Env: append(os.Environ(), "ROUTER_POLICY_CONFIG="+*config)}
		harness := hardwarevalidation.Harness{Runner: runner, Paths: paths}
		result, err := harness.RunMatrix(context.Background(), *runDir, *cases)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "smart-dns":
		fs := flag.NewFlagSet("smart-dns", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		primary := fs.String("primary", "", "primary production Smart DNS resolver")
		secondary := fs.String("secondary", "", "secondary production Smart DNS resolver")
		domain := fs.String("domain", "chatgpt.com", "validation domain")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("smart-dns received unexpected arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		harness := hardwarevalidation.Harness{Runner: hardwarevalidation.ExecRunner{}, Paths: paths}
		result, err := harness.VerifySmartDNSResolvers(context.Background(), hardwarevalidation.SmartDNSOptions{RunDir: *runDir, Primary: *primary, Secondary: *secondary, Domain: *domain})
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "recursion":
		fs := flag.NewFlagSet("recursion", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		route := fs.String("route", "", "VLESS route tag")
		domain := fs.String("domain", "", "probe domain")
		service := fs.String("service", "", "probe service")
		config := fs.String("config", paths.Config, "active FlintRoute config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("recursion received unexpected arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		paths.Config = *config
		runner := hardwarevalidation.ExecRunner{Env: append(os.Environ(), "ROUTER_POLICY_CONFIG="+*config)}
		harness := hardwarevalidation.Harness{Runner: runner, Paths: paths}
		result, err := harness.VerifyProxyRecursion(context.Background(), hardwarevalidation.ProxyRecursionOptions{RunDir: *runDir, Route: *route, Domain: *domain, Service: *service})
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "load":
		fs := flag.NewFlagSet("load", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		plan := fs.String("plan", "", "bounded load plan")
		config := fs.String("config", paths.Config, "active FlintRoute config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *plan == "" || fs.NArg() != 0 {
			return errors.New("load requires --plan and no positional arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		paths.Config = *config
		runner := hardwarevalidation.ExecRunner{Env: append(os.Environ(), "ROUTER_POLICY_CONFIG="+*config)}
		harness := hardwarevalidation.Harness{Runner: runner, Paths: paths}
		result, err := harness.RunLoad(context.Background(), *runDir, *plan)
		if printErr := printJSON(result); printErr != nil {
			return printErr
		}
		return err
	case "finalize":
		fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
		runDir := fs.String("run-dir", "", "evidence run directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("finalize received unexpected arguments")
		}
		if err := hardwarevalidation.ValidateDeviceRunDir(*runDir); err != nil {
			return err
		}
		if err := hardwarevalidation.Finalize(*runDir); err != nil {
			return err
		}
		return printJSON(map[string]any{"finalized": true, "run_dir": filepath.Base(*runDir), "finished_at": time.Now().UTC().Format(time.RFC3339)})
	default:
		return fmt.Errorf("unknown hardware command %q", args[0])
	}
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
