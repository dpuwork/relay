package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Magic bytes to identify the Relay protocol
var MagicBytes = [4]byte{'R', 'L', 'Y', 0x01}

// Opcodes for connection initialization
const (
	OpRegControl uint8 = 0x01 // Agent registering control channel
	OpClientConn uint8 = 0x02 // Client connecting to session
	OpRegData    uint8 = 0x03 // Agent data channel dialout
)

// Opcodes for control channel commands (Relay -> Agent)
const (
	CmdSpawnData uint8 = 0x11 // Relay instructing Agent to spawn data connection
)

// Header represents the initial connection frame sent by clients/agents
type Header struct {
	Opcode        uint8
	SessionID     [16]byte
	SplicingToken [32]byte // Used only for OpRegData
	Token         []byte   // Used for OpRegControl and OpClientConn
}

// ReadHeader reads and parses the connection header from the reader
func ReadHeader(r io.Reader) (*Header, error) {
	// 1. Read and verify Magic bytes
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != MagicBytes {
		return nil, errors.New("invalid protocol magic bytes")
	}

	// 2. Read Opcode
	var opcode uint8
	if err := binary.Read(r, binary.BigEndian, &opcode); err != nil {
		return nil, err
	}

	// 3. Read SessionID
	var sessionID [16]byte
	if _, err := io.ReadFull(r, sessionID[:]); err != nil {
		return nil, err
	}

	header := &Header{
		Opcode:    opcode,
		SessionID: sessionID,
	}

	// 4. Read Opcode-specific payloads
	switch opcode {
	case OpRegControl, OpClientConn:
		// Read token length (2 bytes)
		var tokenLen uint16
		if err := binary.Read(r, binary.BigEndian, &tokenLen); err != nil {
			return nil, err
		}
		if tokenLen > 1024 {
			return nil, errors.New("token length exceeds maximum allowed size (1024 bytes)")
		}
		// Read token bytes
		header.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(r, header.Token); err != nil {
			return nil, err
		}

	case OpRegData:
		// Read SplicingToken (32 bytes)
		if _, err := io.ReadFull(r, header.SplicingToken[:]); err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("unknown connection opcode")
	}

	return header, nil
}

// WriteHeader writes the connection header to the writer
func WriteHeader(w io.Writer, h *Header) error {
	// 1. Write Magic bytes
	if _, err := w.Write(MagicBytes[:]); err != nil {
		return err
	}

	// 2. Write Opcode
	if err := binary.Write(w, binary.BigEndian, h.Opcode); err != nil {
		return err
	}

	// 3. Write SessionID
	if _, err := w.Write(h.SessionID[:]); err != nil {
		return err
	}

	// 4. Write Opcode-specific payloads
	switch h.Opcode {
	case OpRegControl, h.Opcode & OpClientConn: // handles both OpRegControl and OpClientConn
		tokenLen := uint16(len(h.Token))
		if err := binary.Write(w, binary.BigEndian, tokenLen); err != nil {
			return err
		}
		if _, err := w.Write(h.Token); err != nil {
			return err
		}

	case OpRegData:
		if _, err := w.Write(h.SplicingToken[:]); err != nil {
			return err
		}
	}

	return nil
}

// ControlMessage represents a command sent over the Agent Control channel
type ControlMessage struct {
	Cmd           uint8
	SplicingToken [32]byte
}

// ReadControlMessage reads a control command from the agent's control channel
func ReadControlMessage(r io.Reader) (*ControlMessage, error) {
	var cmd uint8
	if err := binary.Read(r, binary.BigEndian, &cmd); err != nil {
		return nil, err
	}

	var token [32]byte
	if _, err := io.ReadFull(r, token[:]); err != nil {
		return nil, err
	}

	return &ControlMessage{
		Cmd:           cmd,
		SplicingToken: token,
	}, nil
}

// WriteControlMessage writes a control command to the agent's control channel
func WriteControlMessage(w io.Writer, msg *ControlMessage) error {
	if err := binary.Write(w, binary.BigEndian, msg.Cmd); err != nil {
		return err
	}
	if _, err := w.Write(msg.SplicingToken[:]); err != nil {
		return err
	}
	return nil
}

// UnwrapTCP extracts the raw *net.TCPConn from a generic net.Conn, supporting
// any potential standard library or custom socket wrappers.
func UnwrapTCP(conn net.Conn) (*net.TCPConn, error) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		return tcp, nil
	}
	// Under extreme circumstances, check if the connection implements a custom sys connection
	type syscallConn interface {
		SyscallConn() (net.Conn, error)
	}
	if sys, ok := conn.(syscallConn); ok {
		if underlying, err := sys.SyscallConn(); err == nil {
			if tcp, ok := underlying.(*net.TCPConn); ok {
				return tcp, nil
			}
		}
	}
	return nil, errors.New("connection is not a raw *net.TCPConn")
}
