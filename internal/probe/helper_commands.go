package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"router-policy/internal/artifact"
	"router-policy/internal/helper"
	"router-policy/internal/secureid"
)

// HelperOpenWrtCommands keeps kernel dataplane inspection behind the root
// helper. The controller never receives an executable/path or shell fragment;
// each operation is a typed, generation-bound read-only request.
type HelperOpenWrtCommands struct {
	socket       string
	binding      artifact.Binding
	manifestHash string
}

func NewHelperOpenWrtCommands(socket string, binding artifact.Binding, manifestHash string) (*HelperOpenWrtCommands, error) {
	if socket == "" || !filepath.IsAbs(socket) || filepath.Base(socket) != "helper.sock" {
		return nil, errors.New("helper socket path is not allowlisted")
	}
	if binding.RevisionID == "" || binding.TransactionID == "" || binding.CandidateHash == "" || manifestHash == "" {
		return nil, errors.New("complete helper probe binding is required")
	}
	return &HelperOpenWrtCommands{socket: socket, binding: binding, manifestHash: manifestHash}, nil
}

func (c *HelperOpenWrtCommands) call(ctx context.Context, request helper.ProbeRequest) ([]byte, error) {
	if c == nil {
		return nil, errors.New("helper probe is unavailable")
	}
	requestID, err := secureid.Hex(12)
	if err != nil {
		return nil, fmt.Errorf("generate helper probe request id: %w", err)
	}
	response, err := helper.Call(ctx, c.socket, helper.Request{
		ProtocolVersion:      helper.ProtocolVersion,
		RequestID:            requestID,
		Command:              "probe." + request.Operation,
		Generation:           c.binding.RevisionID,
		RevisionID:           c.binding.RevisionID,
		TransactionID:        "probe",
		CandidateHash:        c.binding.CandidateHash,
		ArtifactManifestHash: c.manifestHash,
		Probe:                &request,
	})
	if err != nil {
		return nil, err
	}
	payload, ok := response.Evidence["payload"]
	if !ok {
		return nil, errors.New("helper probe response has no payload")
	}
	return []byte(payload), nil
}

func (c *HelperOpenWrtCommands) RouteGet(ctx context.Context, destination, mark string) (KernelRoute, error) {
	raw, err := c.call(ctx, helper.ProbeRequest{Operation: "route_get", Destination: destination, Mark: mark})
	if err != nil {
		return KernelRoute{}, err
	}
	return parseRouteGet(raw)
}

func (c *HelperOpenWrtCommands) Rules(ctx context.Context) ([]KernelRule, error) {
	var all []KernelRule
	for _, family := range []string{"4", "6"} {
		raw, err := c.call(ctx, helper.ProbeRequest{Operation: "rules", Family: family})
		if err != nil {
			return nil, err
		}
		rules, err := parseRules(raw, family)
		if err != nil {
			return nil, err
		}
		all = append(all, rules...)
	}
	return all, nil
}

func (c *HelperOpenWrtCommands) HasDefaultRoute(ctx context.Context, family string, table int) (bool, error) {
	raw, err := c.call(ctx, helper.ProbeRequest{Operation: "default_route", Family: family, Table: table})
	if err != nil {
		return false, err
	}
	var routes []map[string]any
	if err := decodeStrictJSON(raw, &routes); err != nil {
		return false, err
	}
	return len(routes) > 0, nil
}

func (c *HelperOpenWrtCommands) NFTPolicy(ctx context.Context, routeTag string) (NFTPolicy, error) {
	raw, err := c.call(ctx, helper.ProbeRequest{Operation: "nft_policy", RouteTag: routeTag})
	if err != nil {
		return NFTPolicy{}, err
	}
	return parseNFTPolicy(raw, routeTag)
}

func (c *HelperOpenWrtCommands) ProcessRunning(ctx context.Context, process string) (bool, error) {
	raw, err := c.call(ctx, helper.ProbeRequest{Operation: "process", Process: process})
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("malformed process probe response")
	}
}

func (c *HelperOpenWrtCommands) ConntrackMark(localIP, connectedIP string) (string, error) {
	if net.ParseIP(localIP) == nil || net.ParseIP(connectedIP) == nil {
		return "", errors.New("conntrack_tuple_incomplete")
	}
	raw, err := c.call(context.Background(), helper.ProbeRequest{Operation: "conntrack", LocalIP: localIP, ConnectedIP: connectedIP})
	if err != nil {
		return "", err
	}
	mark := strings.TrimSpace(string(raw))
	value, err := parseSocketMark(mark)
	if err != nil {
		return "", errors.New("malformed conntrack mark")
	}
	return formatSocketMark(value), nil
}

var _ OpenWrtCommands = (*HelperOpenWrtCommands)(nil)
