package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestHeaderSerialization(t *testing.T) {
	sessionID := [16]byte{0xAA, 0xBB, 0xCC, 0xDD}
	splicingToken := [32]byte{0x01, 0x02, 0x03, 0x04}
	clientToken := []byte("test-auth-token-bytes")

	tests := []struct {
		name   string
		header *Header
	}{
		{
			name: "OpRegControl",
			header: &Header{
				Opcode:    OpRegControl,
				SessionID: sessionID,
				Token:     clientToken,
			},
		},
		{
			name: "OpClientConn",
			header: &Header{
				Opcode:    OpClientConn,
				SessionID: sessionID,
				Token:     clientToken,
			},
		},
		{
			name: "OpRegData",
			header: &Header{
				Opcode:        OpRegData,
				SessionID:     sessionID,
				SplicingToken: splicingToken,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteHeader(&buf, tt.header)
			if err != nil {
				t.Fatalf("Failed to write header: %v", err)
			}

			decoded, err := ReadHeader(&buf)
			if err != nil {
				t.Fatalf("Failed to read header: %v", err)
			}

			if decoded.Opcode != tt.header.Opcode {
				t.Errorf("Opcode mismatch: got %v, want %v", decoded.Opcode, tt.header.Opcode)
			}
			if decoded.SessionID != tt.header.SessionID {
				t.Errorf("SessionID mismatch: got %x, want %x", decoded.SessionID, tt.header.SessionID)
			}
			if tt.header.Opcode == OpRegData && decoded.SplicingToken != tt.header.SplicingToken {
				t.Errorf("SplicingToken mismatch")
			}
			if (tt.header.Opcode == OpRegControl || tt.header.Opcode == OpClientConn) && !bytes.Equal(decoded.Token, tt.header.Token) {
				t.Errorf("Token mismatch")
			}
		})
	}
}

func TestControlMessageSerialization(t *testing.T) {
	var buf bytes.Buffer
	msg := &ControlMessage{
		Cmd:           CmdSpawnData,
		SplicingToken: [32]byte{0x11, 0x22, 0x33, 0x44},
	}

	err := WriteControlMessage(&buf, msg)
	if err != nil {
		t.Fatalf("WriteControlMessage failed: %v", err)
	}

	decoded, err := ReadControlMessage(&buf)
	if err != nil {
		t.Fatalf("ReadControlMessage failed: %v", err)
	}

	if decoded.Cmd != msg.Cmd {
		t.Errorf("Cmd mismatch: got %v, want %v", decoded.Cmd, msg.Cmd)
	}
	if decoded.SplicingToken != msg.SplicingToken {
		t.Errorf("SplicingToken mismatch")
	}
}

func TestUnwrapTCP(t *testing.T) {
	// Test with a real TCP connection
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind tcp listener: %v", err)
	}
	defer l.Close()

	go func() {
		conn, _ := l.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial tcp listener: %v", err)
	}
	defer conn.Close()

	tcpConn, err := UnwrapTCP(conn)
	if err != nil || tcpConn == nil {
		t.Errorf("UnwrapTCP failed on real TCP connection: %v", err)
	}

	// Test with a mock connection (net.Pipe)
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()

	_, err = UnwrapTCP(p1)
	if err == nil {
		t.Errorf("UnwrapTCP should have failed on net.Pipe(), but got nil error")
	}
}
