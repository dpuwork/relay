package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"relay/pkg/crypto"
	"relay/pkg/protocol"
)

// setupTestRelay initializes an in-process RelayServer and returns it along with its address.
func setupTestRelay(t testing.TB) (*RelayServer, string, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	server := NewRelayServer("127.0.0.1:0", pubKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	server.listener = l

	go func() {
		for {
			conn, err := server.listener.Accept()
			if err != nil {
				return
			}
			go server.handleConnection(conn)
		}
	}()

	return server, l.Addr().String(), privKey
}

// TestRelayIntegration performs a full E2E setup in-process ensuring the state machine
// properly handles matchmaking and data proxying.
func TestRelayIntegration(t *testing.T) {
	server, relayAddr, privKey := setupTestRelay(t)
	defer server.Close()

	// 1. Setup Mock Target Service
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start target: %v", err)
	}
	defer targetListener.Close()

	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Simple echo server for testing
		io.Copy(conn, conn)
	}()

	// 2. Generate Session Tokens
	var sessionID [16]byte
	io.ReadFull(rand.Reader, sessionID[:])
	expiresAt := time.Now().Unix() + 60
	agentToken := crypto.GenerateToken(sessionID, crypto.RoleControl, expiresAt, privKey)
	clientToken := crypto.GenerateToken(sessionID, crypto.RoleClient, expiresAt, privKey)

	// 3. Mock Agent
	agentCtrlConn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatalf("Agent dial failed: %v", err)
	}
	defer agentCtrlConn.Close()

	err = protocol.WriteHeader(agentCtrlConn, &protocol.Header{
		Opcode:    protocol.OpRegControl,
		SessionID: sessionID,
		Token:     agentToken,
	})
	if err != nil {
		t.Fatalf("Agent RegControl write failed: %v", err)
	}

	// Agent control loop
	go func() {
		cmd, err := protocol.ReadControlMessage(agentCtrlConn)
		if err != nil {
			return
		}
		if cmd.Cmd == protocol.CmdSpawnData {
			// Connect to target
			localConn, _ := net.Dial("tcp", targetListener.Addr().String())
			// Connect to relay data plane
			relayDataConn, _ := net.Dial("tcp", relayAddr)

			protocol.WriteHeader(relayDataConn, &protocol.Header{
				Opcode:        protocol.OpRegData,
				SessionID:     sessionID,
				SplicingToken: cmd.SplicingToken,
			})

			go io.Copy(localConn, relayDataConn)
			go io.Copy(relayDataConn, localConn)
		}
	}()

	// Small delay to ensure Agent is registered
	time.Sleep(50 * time.Millisecond)

	// 4. Client Connection
	clientConn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatalf("Client dial failed: %v", err)
	}
	defer clientConn.Close()

	err = protocol.WriteHeader(clientConn, &protocol.Header{
		Opcode:    protocol.OpClientConn,
		SessionID: sessionID,
		Token:     clientToken,
	})
	if err != nil {
		t.Fatalf("Client connection write failed: %v", err)
	}

	// 5. Test transmission (Echo test)
	testPayload := []byte("Zero-copy TCP relay integration test!\n")
	_, err = clientConn.Write(testPayload)
	if err != nil {
		t.Fatalf("Client write failed: %v", err)
	}

	response := make([]byte, len(testPayload))
	_, err = io.ReadFull(clientConn, response)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	if string(response) != string(testPayload) {
		t.Fatalf("Echo mismatch. Got: %s, Want: %s", response, testPayload)
	}
}

// BenchmarkRelayThroughput tests the throughput and zero-allocation properties
// (on supported OS) of the kernel-space splicing logic under load.
func BenchmarkRelayThroughput(b *testing.B) {
	server, relayAddr, privKey := setupTestRelay(b)
	defer server.Close()

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to start target: %v", err)
	}
	defer targetListener.Close()

	// Accept target connection and store it
	var targetConn net.Conn
	var targetWg sync.WaitGroup
	targetWg.Add(1)
	go func() {
		defer targetWg.Done()
		conn, err := targetListener.Accept()
		if err == nil {
			targetConn = conn
		}
	}()

	var sessionID [16]byte
	io.ReadFull(rand.Reader, sessionID[:])
	expiresAt := time.Now().Unix() + 300
	agentToken := crypto.GenerateToken(sessionID, crypto.RoleControl, expiresAt, privKey)
	clientToken := crypto.GenerateToken(sessionID, crypto.RoleClient, expiresAt, privKey)

	// Mock Agent
	agentCtrlConn, _ := net.Dial("tcp", relayAddr)
	defer agentCtrlConn.Close()
	_ = protocol.WriteHeader(agentCtrlConn, &protocol.Header{
		Opcode:    protocol.OpRegControl,
		SessionID: sessionID,
		Token:     agentToken,
	})

	go func() {
		cmd, _ := protocol.ReadControlMessage(agentCtrlConn)
		if cmd.Cmd == protocol.CmdSpawnData {
			localConn, _ := net.Dial("tcp", targetListener.Addr().String())
			relayDataConn, _ := net.Dial("tcp", relayAddr)
			_ = protocol.WriteHeader(relayDataConn, &protocol.Header{
				Opcode:        protocol.OpRegData,
				SessionID:     sessionID,
				SplicingToken: cmd.SplicingToken,
			})
			go io.Copy(localConn, relayDataConn)
			go io.Copy(relayDataConn, localConn)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Mock Client
	clientConn, _ := net.Dial("tcp", relayAddr)
	defer clientConn.Close()
	_ = protocol.WriteHeader(clientConn, &protocol.Header{
		Opcode:    protocol.OpClientConn,
		SessionID: sessionID,
		Token:     clientToken,
	})

	targetWg.Wait() // wait for the target to be connected
	if targetConn == nil {
		b.Fatalf("Target connection failed")
	}
	defer targetConn.Close()

	// Ensure matchmaking completes and sockets are spliced
	time.Sleep(100 * time.Millisecond)

	chunkSize := 32 * 1024 // 32KB chunks
	payload := make([]byte, chunkSize)
	io.ReadFull(rand.Reader, payload)

	readBuf := make([]byte, chunkSize)
	errCh := make(chan error, 1)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(chunkSize))

	// Start reading on the target end
	go func() {
		for i := 0; i < b.N; i++ {
			_, err := io.ReadFull(targetConn, readBuf)
			if err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	// Push bytes through the relay
	for i := 0; i < b.N; i++ {
		_, err := clientConn.Write(payload)
		if err != nil {
			b.Fatalf("Write error: %v", err)
		}
	}

	if err := <-errCh; err != nil {
		b.Fatalf("Read error: %v", err)
	}
}
