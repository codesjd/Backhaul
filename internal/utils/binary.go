package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func SendBinaryString(conn interface{}, message string) error {
	// Header size
	const headerSize = 2

	// Create a buffer with the appropriate size for the message
	buf := make([]byte, headerSize+len(message))

	// Encode the length of the message as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf[:headerSize], uint16(len(message)))

	// Copy the message into the buffer after the length
	copy(buf[headerSize:], message)

	switch c := conn.(type) {
	case net.Conn:
		// Send the buffer over the connection
		if _, err := c.Write(buf); err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}

	default:
		// Handle unsupported connection types
		return fmt.Errorf("unsupported connection type: %T", conn)
	}
	// Successful
	return nil
}

func ReceiveBinaryString(conn interface{}) (string, error) {
	// Header size
	const headerSize = 2

	// Create a buffer to read the first 2 bytes (the length of the message)
	lenBuf := make([]byte, headerSize)

	switch c := conn.(type) {
	case net.Conn:
		// Read exactly 2 bytes for the message length
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return "", fmt.Errorf("failed to read message length from net.Conn: %w", err)
		}

	default:
		return "", fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Decode the length of the message from the 2-byte buffer
	messageLength := binary.BigEndian.Uint16(lenBuf[:2])

	// Create a buffer of the appropriate size to hold the message
	messageBuf := make([]byte, messageLength)

	switch c := conn.(type) {
	case net.Conn:
		if _, err := io.ReadFull(c, messageBuf); err != nil {
			return "", fmt.Errorf("failed to read message from net.Conn: %w", err)
		}

	default:
		return "", fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Convert the message buffer to a string and return it
	return string(messageBuf), nil
}

func SendBinaryTransportString(conn interface{}, message string, transport byte) error {
	// Header size
	const headerSize = 3

	// Create a buffer with the appropriate size for the message
	buf := make([]byte, headerSize+len(message))

	// Encode the length of the message as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf[:headerSize], uint16(len(message)))

	// encode the transport tyope
	buf[2] = transport

	// Copy the message into the buffer after the length
	copy(buf[headerSize:], message)

	switch c := conn.(type) {
	case net.Conn:
		// Send the buffer over the connection
		if _, err := c.Write(buf); err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}

	default:
		// Handle unsupported connection types
		return fmt.Errorf("unsupported connection type: %T", conn)
	}
	// Successful
	return nil
}

func ReceiveBinaryTransportString(conn interface{}) (string, byte, error) {
	// Header size
	const headerSize = 3

	// Create a buffer to read the first 2 bytes (the length of the message)
	lenBuf := make([]byte, headerSize)

	switch c := conn.(type) {
	case net.Conn:
		// Read exactly 2 bytes for the message length
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read message length from net.Conn: %w", err)
		}

	default:
		return "", 0, fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Decode the length of the message from the 2-byte buffer
	messageLength := binary.BigEndian.Uint16(lenBuf[:2])

	// decode the transport
	transport := lenBuf[2]

	// Create a buffer of the appropriate size to hold the message
	messageBuf := make([]byte, messageLength)

	switch c := conn.(type) {
	case net.Conn:
		if _, err := io.ReadFull(c, messageBuf); err != nil {
			return "", 0, fmt.Errorf("failed to read message from net.Conn: %w", err)
		}

	default:
		return "", 0, fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Convert the message buffer to a string and return it
	return string(messageBuf), transport, nil
}

// SendStripeHeader identifies which striped group a freshly opened stream
// belongs to: groupID correlates legs opened for the same logical
// connection, index/total let the receiver know how many legs to wait for
// before it can assemble them, parity is how many of those total legs carry
// Reed-Solomon parity shards rather than data (0 for plain striping, so the
// data-shard count is always total-parity), and remoteAddr is carried once
// per leg since every leg is otherwise indistinguishable from a plain tunnel
// stream.
func SendStripeHeader(conn net.Conn, groupID uint32, index, total, parity uint8, remoteAddr string) error {
	const headerSize = 4 + 1 + 1 + 1 + 2 // groupID + index + total + parity + addr length
	buf := make([]byte, headerSize+len(remoteAddr))

	binary.BigEndian.PutUint32(buf[0:4], groupID)
	buf[4] = index
	buf[5] = total
	buf[6] = parity
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(remoteAddr)))
	copy(buf[9:], remoteAddr)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send stripe header: %w", err)
	}
	return nil
}

// ReceiveStripeHeader reads a header written by SendStripeHeader.
func ReceiveStripeHeader(conn net.Conn) (groupID uint32, index, total, parity uint8, remoteAddr string, err error) {
	const headerSize = 4 + 1 + 1 + 1 + 2
	head := make([]byte, headerSize)
	if _, err = io.ReadFull(conn, head); err != nil {
		return 0, 0, 0, 0, "", fmt.Errorf("failed to read stripe header: %w", err)
	}

	groupID = binary.BigEndian.Uint32(head[0:4])
	index = head[4]
	total = head[5]
	parity = head[6]
	addrLen := binary.BigEndian.Uint16(head[7:9])

	addrBuf := make([]byte, addrLen)
	if addrLen > 0 {
		if _, err = io.ReadFull(conn, addrBuf); err != nil {
			return 0, 0, 0, 0, "", fmt.Errorf("failed to read stripe header address: %w", err)
		}
	}

	return groupID, index, total, parity, string(addrBuf), nil
}

// SendPort sends the port number as a 2-byte big-endian unsigned integer.
func SendBinaryInt(conn net.Conn, port uint16) error {
	// Create a 2-byte slice to hold the port number
	buf := make([]byte, 2)

	// Encode the port number as a big-endian 2-byte unsigned integer
	binary.BigEndian.PutUint16(buf, port)

	// Send the 2-byte buffer over the connection
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send port number %d: %w", port, err)
	}

	// Successful
	return nil
}

// ReceivePort reads a 2-byte big-endian unsigned integer directly from the connection
func ReceiveBinaryInt(conn net.Conn) (uint16, error) {
	var port uint16

	// Use binary.Read to read the port directly from the connection
	err := binary.Read(conn, binary.BigEndian, &port)
	if err != nil {
		return 0, fmt.Errorf("failed to read port number from connection: %w", err)
	}

	// Successful
	return port, nil
}

func SendBinaryByte(conn interface{}, message byte) error {
	// Create a 1-byte buffer and send the message
	messageBuf := [1]byte{message}

	switch c := conn.(type) {
	case net.Conn:
		if _, err := c.Write(messageBuf[:]); err != nil {
			return fmt.Errorf("failed to read message from net.Conn: %w", err)
		}

	default:
		return fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Successful
	return nil
}

func ReceiveBinaryByte(conn net.Conn) (byte, error) {
	var messageBuf [1]byte

	switch c := conn.(type) {
	case net.Conn:
		if _, err := io.ReadFull(c, messageBuf[:]); err != nil {
			return 0, fmt.Errorf("failed to read message from net.Conn: %w", err)
		}

	default:
		return 0, fmt.Errorf("unsupported connection type: %T", conn)
	}

	// Convert the message buffer to a string and return it
	return messageBuf[0], nil
}
