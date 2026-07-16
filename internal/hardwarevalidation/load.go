package hardwarevalidation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-policy/internal/probe"
)

type LoadPlan struct {
	Workers    int          `json:"workers"`
	Iterations int          `json:"iterations"`
	Cases      []MatrixCase `json:"cases"`
}

type LoadResult struct {
	Sequence  int      `json:"sequence"`
	CaseID    string   `json:"case_id"`
	Status    string   `json:"status"`
	LatencyMS float64  `json:"latency_ms"`
	Reasons   []string `json:"reasons,omitempty"`
	CheckedAt string   `json:"checked_at"`
}

type LoadSummary struct {
	Workers     int     `json:"workers"`
	Iterations  int     `json:"iterations"`
	Total       int     `json:"total"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	MedianMS    float64 `json:"median_ms"`
	P95MS       float64 `json:"p95_ms"`
	ElapsedMS   float64 `json:"elapsed_ms"`
	SingleNode  bool    `json:"single_node"`
	MultiClient string  `json:"multi_client"`
}

type ResourceSample struct {
	CollectedAt       string  `json:"collected_at"`
	Phase             string  `json:"phase"`
	Load1             float64 `json:"load_1"`
	MemoryAvailableKB int64   `json:"memory_available_kb"`
	ConntrackCount    int64   `json:"conntrack_count"`
}

func (h Harness) RunLoad(ctx context.Context, runDir, planPath string) (LoadSummary, error) {
	if h.Runner == nil {
		return LoadSummary{}, errors.New("runner is required")
	}
	if err := ensureRunDir(runDir); err != nil {
		return LoadSummary{}, err
	}
	raw, err := readBounded(planPath, maxCasesBytes)
	if err != nil {
		return LoadSummary{}, err
	}
	var plan LoadPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return LoadSummary{}, fmt.Errorf("decode load plan: %w", err)
	}
	if plan.Workers < 1 || plan.Workers > 16 || plan.Iterations < 1 || plan.Iterations > 64 || len(plan.Cases) == 0 || len(plan.Cases) > 32 {
		return LoadSummary{}, errors.New("load plan exceeds bounded worker, iteration or case limits")
	}
	seen := map[string]struct{}{}
	for _, testCase := range plan.Cases {
		if testCase.SkipReason != "" {
			return LoadSummary{}, fmt.Errorf("load case %s cannot be skipped", testCase.ID)
		}
		if err := validateCase(testCase, seen); err != nil {
			return LoadSummary{}, err
		}
		seen[testCase.ID] = struct{}{}
	}
	resourcePath := filepath.Join(runDir, "resource-samples.jsonl")
	resourceFile, err := os.OpenFile(resourcePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return LoadSummary{}, err
	}
	defer resourceFile.Close()
	if err := appendJSON(resourceFile, collectResourceSample("before", h.now())); err != nil {
		return LoadSummary{}, err
	}

	type job struct {
		sequence int
		testCase MatrixCase
	}
	total := plan.Iterations * len(plan.Cases)
	jobs := make(chan job)
	results := make(chan LoadResult, total)
	var workers sync.WaitGroup
	started := time.Now()
	for worker := 0; worker < plan.Workers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				begin := time.Now()
				result := LoadResult{Sequence: item.sequence, CaseID: item.testCase.ID, CheckedAt: h.now().Format(time.RFC3339)}
				raw, runErr := h.Runner.Run(ctx, h.Paths.RouterPolicy, "probe-route", "--no-persist", "--route", item.testCase.Route, item.testCase.Domain, item.testCase.Service)
				result.LatencyMS = float64(time.Since(begin)) / float64(time.Millisecond)
				if runErr != nil {
					result.Status, result.Reasons = "FAIL", []string{"probe command failed"}
					results <- result
					continue
				}
				var routeResult probe.RouteResult
				if err := json.Unmarshal(raw, &routeResult); err != nil {
					result.Status, result.Reasons = "FAIL", []string{"probe returned invalid JSON"}
					results <- result
					continue
				}
				result.Reasons = evaluateCase(item.testCase, routeResult)
				if len(result.Reasons) == 0 {
					result.Status = "PASS"
				} else {
					result.Status = "FAIL"
				}
				results <- result
			}
		}()
	}
	go func() {
		sequence := 0
		for iteration := 0; iteration < plan.Iterations; iteration++ {
			for _, testCase := range plan.Cases {
				jobs <- job{sequence: sequence, testCase: testCase}
				sequence++
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	collected := make([]LoadResult, 0, total)
	for result := range results {
		collected = append(collected, result)
	}
	elapsed := time.Since(started)
	sort.Slice(collected, func(i, j int) bool { return collected[i].Sequence < collected[j].Sequence })
	resultFile, err := os.OpenFile(filepath.Join(runDir, "load-results.jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return LoadSummary{}, err
	}
	latencies := make([]float64, 0, len(collected))
	summary := LoadSummary{Workers: plan.Workers, Iterations: plan.Iterations, Total: len(collected), ElapsedMS: float64(elapsed) / float64(time.Millisecond), SingleNode: true, MultiClient: "NOT_TESTED"}
	for _, result := range collected {
		if err := appendJSON(resultFile, result); err != nil {
			_ = resultFile.Close()
			return LoadSummary{}, err
		}
		latencies = append(latencies, result.LatencyMS)
		if result.Status == "PASS" {
			summary.Passed++
		} else {
			summary.Failed++
		}
	}
	if err := resultFile.Close(); err != nil {
		return LoadSummary{}, err
	}
	sort.Float64s(latencies)
	summary.MedianMS = loadPercentile(latencies, 0.50)
	summary.P95MS = loadPercentile(latencies, 0.95)
	if err := appendJSON(resourceFile, collectResourceSample("after", h.now())); err != nil {
		return LoadSummary{}, err
	}
	if err := writeJSON(filepath.Join(runDir, "load-summary.json"), summary); err != nil {
		return LoadSummary{}, err
	}
	if summary.Failed > 0 {
		return summary, fmt.Errorf("load run has %d failed probes", summary.Failed)
	}
	return summary, nil
}

func collectResourceSample(phase string, now time.Time) ResourceSample {
	sample := ResourceSample{CollectedAt: now.Format(time.RFC3339), Phase: phase}
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			sample.Load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "MemAvailable:" {
				sample.MemoryAvailableKB, _ = strconv.ParseInt(fields[1], 10, 64)
				break
			}
		}
	}
	if raw, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		sample.ConntrackCount, _ = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	}
	return sample
}

func loadPercentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1)*fraction + 0.5)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
