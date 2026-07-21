package hardwarevalidation

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"router-policy/internal/config"
)

func exerciseSOCKSTransport(ctx context.Context, cfg *config.Config, route config.Route, protocol, domain string) transportOutcome {
	if route.SOCKS5 == "" {
		return transportOutcome{err: errors.New("VLESS SOCKS endpoint is missing")}
	}
	switch protocol {
	case "dns_tcp_53":
		resolver, err := resolverForRoute(cfg, route)
		if err != nil {
			return transportOutcome{err: err}
		}
		connection, err := dialSOCKS5TCP(ctx, route.SOCKS5, resolver)
		if err != nil {
			return transportOutcome{err: err}
		}
		defer connection.Close()
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		dnsConnection := &dns.Conn{Conn: connection}
		if err := dnsConnection.WriteMsg(message); err != nil {
			return transportOutcome{err: err}
		}
		response, err := dnsConnection.ReadMsg()
		if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
			if err == nil {
				err = errors.New("SOCKS DNS response was empty")
			}
			return transportOutcome{err: err}
		}
		return transportOutcome{responseReceived: true}
	case "dns_udp_53":
		resolver, err := resolverForRoute(cfg, route)
		if err != nil {
			return transportOutcome{err: err}
		}
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		payload, err := message.Pack()
		if err != nil {
			return transportOutcome{err: err}
		}
		responsePayload, err := exchangeSOCKS5UDP(ctx, route.SOCKS5, resolver, payload, true)
		if err != nil {
			return transportOutcome{err: err}
		}
		response := new(dns.Msg)
		if err := response.Unpack(responsePayload); err != nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
			return transportOutcome{err: errors.New("SOCKS UDP DNS response was invalid")}
		}
		return transportOutcome{responseReceived: true, packetWritten: true}
	case "tcp_80", "tcp_443":
		port := "80"
		if protocol == "tcp_443" {
			port = "443"
		}
		connection, err := dialSOCKS5TCP(ctx, route.SOCKS5, net.JoinHostPort(domain, port))
		if err != nil {
			return transportOutcome{err: err}
		}
		_ = connection.Close()
		return transportOutcome{connected: true}
	case "udp_443":
		payload := make([]byte, 1200)
		payload[0] = 0xc0
		_, err := exchangeSOCKS5UDP(ctx, route.SOCKS5, net.JoinHostPort(domain, "443"), payload, false)
		if err != nil {
			return transportOutcome{err: err}
		}
		return transportOutcome{packetWritten: true}
	default:
		return transportOutcome{err: errors.New("unsupported SOCKS transport protocol")}
	}
}

func dialSOCKS5TCP(ctx context.Context, proxyAddress, targetAddress string) (net.Conn, error) {
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socksGreeting(connection); err != nil {
		connection.Close()
		return nil, err
	}
	request, err := socksRequest(0x01, targetAddress)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if _, err := connection.Write(request); err != nil {
		connection.Close()
		return nil, err
	}
	if _, err := readSOCKSReply(connection); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func exchangeSOCKS5UDP(ctx context.Context, proxyAddress, targetAddress string, payload []byte, waitResponse bool) ([]byte, error) {
	control, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socksGreeting(control); err != nil {
		return nil, err
	}
	request, err := socksRequest(0x03, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	if _, err := control.Write(request); err != nil {
		return nil, err
	}
	relay, err := readSOCKSReply(control)
	if err != nil {
		return nil, err
	}
	relayHost, relayPort, err := net.SplitHostPort(relay)
	if err != nil {
		return nil, err
	}
	if relayHost == "0.0.0.0" || relayHost == "::" {
		relayHost, _, _ = net.SplitHostPort(proxyAddress)
		relay = net.JoinHostPort(relayHost, relayPort)
	}
	udpConnection, err := net.DialTimeout("udp", relay, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer udpConnection.Close()
	_ = udpConnection.SetDeadline(time.Now().Add(5 * time.Second))
	header, err := socksUDPHeader(targetAddress)
	if err != nil {
		return nil, err
	}
	if _, err := udpConnection.Write(append(header, payload...)); err != nil {
		return nil, err
	}
	if !waitResponse {
		return nil, nil
	}
	buffer := make([]byte, 64<<10)
	n, err := udpConnection.Read(buffer)
	if err != nil {
		return nil, err
	}
	offset, err := socksUDPPayloadOffset(buffer[:n])
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer[offset:n]...), nil
}

func socksGreeting(connection net.Conn) error {
	if _, err := connection.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if response[0] != 0x05 || response[1] != 0x00 {
		return errors.New("SOCKS authentication was rejected")
	}
	return nil
}

func socksRequest(command byte, target string) ([]byte, error) {
	address, err := socksAddress(target)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x05, command, 0x00}, address...), nil
}

func socksAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	parsed := net.ParseIP(host)
	var out []byte
	if ipv4 := parsed.To4(); ipv4 != nil {
		out = append([]byte{0x01}, ipv4...)
	} else if ipv6 := parsed.To16(); ipv6 != nil {
		out = append([]byte{0x04}, ipv6...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid SOCKS target host")
		}
		out = append([]byte{0x03, byte(len(host))}, []byte(host)...)
	}
	return append(out, byte(port>>8), byte(port)), nil
}

func readSOCKSReply(connection net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return "", errors.New("SOCKS request was rejected")
	}
	host, err := readSOCKSHost(connection, header[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func readSOCKSHost(reader io.Reader, addressType byte) (string, error) {
	size := 0
	switch addressType {
	case 0x01:
		size = 4
	case 0x04:
		size = 16
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", err
		}
		size = int(length[0])
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	if addressType == 0x03 {
		return string(value), nil
	}
	return net.IP(value).String(), nil
}

func socksUDPHeader(target string) ([]byte, error) {
	address, err := socksAddress(target)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x00, 0x00, 0x00}, address...), nil
}

func socksUDPPayloadOffset(packet []byte) (int, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, errors.New("invalid SOCKS UDP response")
	}
	offset := 4
	switch packet[3] {
	case 0x01:
		offset += 4
	case 0x04:
		offset += 16
	case 0x03:
		if len(packet) <= offset {
			return 0, errors.New("truncated SOCKS UDP response")
		}
		offset += 1 + int(packet[offset])
	default:
		return 0, errors.New("unsupported SOCKS UDP address type")
	}
	offset += 2
	if offset > len(packet) {
		return 0, errors.New("truncated SOCKS UDP response")
	}
	return offset, nil
}
