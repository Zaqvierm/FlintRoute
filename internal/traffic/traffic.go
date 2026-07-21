package traffic

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InterfaceCounters struct {
	Name      string `json:"name"`
	RXBytes   uint64 `json:"rx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	RXErrors  uint64 `json:"rx_errors"`
	TXBytes   uint64 `json:"tx_bytes"`
	TXPackets uint64 `json:"tx_packets"`
	TXErrors  uint64 `json:"tx_errors"`
}

type Snapshot struct {
	Status     string              `json:"status"`
	Source     string              `json:"source"`
	Collected  time.Time           `json:"collected_at"`
	Interfaces []InterfaceCounters `json:"interfaces"`
	Reason     string              `json:"reason,omitempty"`
}

func ReadProcNetDev(path string, now time.Time) Snapshot {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{Status: "unavailable", Source: "procfs", Collected: now.UTC(), Interfaces: []InterfaceCounters{}, Reason: "network counters unavailable"}
	}
	defer file.Close()
	interfaces, err := ParseProcNetDev(file)
	if err != nil {
		return Snapshot{Status: "unavailable", Source: "procfs", Collected: now.UTC(), Interfaces: []InterfaceCounters{}, Reason: "network counters malformed"}
	}
	return Snapshot{Status: "OK", Source: "procfs", Collected: now.UTC(), Interfaces: interfaces}
}

func ParseProcNetDev(reader io.Reader) ([]InterfaceCounters, error) {
	scanner := bufio.NewScanner(reader)
	interfaces := make([]InterfaceCounters, 0, 8)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		fields := strings.Fields(line[separator+1:])
		if name == "" || len(fields) < 16 {
			return nil, fmt.Errorf("invalid network device counter row")
		}
		values := make([]uint64, 16)
		for i := range values {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse counters for %s: %w", name, err)
			}
			values[i] = value
		}
		interfaces = append(interfaces, InterfaceCounters{
			Name: name, RXBytes: values[0], RXPackets: values[1], RXErrors: values[2],
			TXBytes: values[8], TXPackets: values[9], TXErrors: values[10],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	return interfaces, nil
}
