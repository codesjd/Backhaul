package handlers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// ProxyProtocolHeader builds the v2 header describing a src->dst flow. Kept
// separate from WriteProxyProtocol because a WebSocket tunnel leg is not an
// io.Writer - the header has to leave as a binary frame, not a raw write.
func ProxyProtocolHeader(src, dst net.Addr) ([]byte, error) {
	srcAddr, ok := src.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("source connection address is not a TCP address")
	}
	dstAddr, ok := dst.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("destination connection address is not a TCP address")
	}

	header, err := buildProxyProtocolV2Header(srcAddr.IP.String(), dstAddr.IP.String(), srcAddr.Port, dstAddr.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to build Proxy Protocol v2 header: %v", err)
	}
	return header, nil
}

func WriteProxyProtocol(from, to net.Conn) error {
	header, err := ProxyProtocolHeader(from.RemoteAddr(), to.RemoteAddr())
	if err != nil {
		return err
	}

	// Send the Proxy Protocol v2 header
	if _, err := to.Write(header); err != nil {
		return fmt.Errorf("failed to send Proxy Protocol v2 header: %v", err)
	}
	return nil
}
func buildProxyProtocolV2Header(srcIP, dstIP string, srcPort, dstPort int) ([]byte, error) {
	var buf bytes.Buffer

	// Magic signature for Proxy Protocol v2
	buf.Write([]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})

	// Version and command (v2 with PROXY command)
	buf.WriteByte(0x21)

	// Determine IP address type
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	if src == nil || dst == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	var familyAndProtocol byte
	var addressLength uint16
	if src.To4() != nil && dst.To4() != nil {
		// IPv4
		familyAndProtocol = 0x11 // IPv4 + TCP
		addressLength = 12
		buf.WriteByte(familyAndProtocol)
		binary.Write(&buf, binary.BigEndian, addressLength)
		buf.Write(src.To4()) // Source IPv4 address
		buf.Write(dst.To4()) // Destination IPv4 address
	} else if src.To16() != nil && dst.To16() != nil {
		// IPv6
		familyAndProtocol = 0x21 // IPv6 + TCP
		addressLength = 36
		buf.WriteByte(familyAndProtocol)
		binary.Write(&buf, binary.BigEndian, addressLength)
		buf.Write(src.To16()) // Source IPv6 address
		buf.Write(dst.To16()) // Destination IPv6 address
	} else {
		return nil, fmt.Errorf("mismatched IP versions (src: %s, dst: %s)", srcIP, dstIP)
	}

	// Write source and destination ports
	binary.Write(&buf, binary.BigEndian, uint16(srcPort))
	binary.Write(&buf, binary.BigEndian, uint16(dstPort))

	return buf.Bytes(), nil
}
