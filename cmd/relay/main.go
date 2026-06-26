package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"relay/pkg/crypto"
	"relay/pkg/protocol"
	"relay/pkg/qr"
)

type RelayServer struct {
	listener       net.Listener
	validator      *crypto.TokenValidator
	controlStreams sync.Map // Key: [16]byte (SessionID), Value: net.Conn (control socket)
	waitingRoom    sync.Map // Key: [32]byte (SplicingToken), Value: chan net.Conn
}

func NewRelayServer(addr string, pubKey ed25519.PublicKey) *RelayServer {
	return &RelayServer{
		validator: crypto.NewTokenValidator(pubKey),
	}
}

func main() {
	addr := flag.String("addr", ":9090", "TCP address to listen on")
	pubKeyHex := flag.String("pubkey", "", "Ed25519 public key in hex (if empty, one will be generated for testing)")
	flag.Parse()

	var pubKey ed25519.PublicKey
	var privKey ed25519.PrivateKey
	var err error

	if *pubKeyHex != "" {
		pubKeyBytes, err := hex.DecodeString(*pubKeyHex)
		if err != nil {
			log.Fatalf("Failed to decode public key hex: %v", err)
		}
		if len(pubKeyBytes) != ed25519.PublicKeySize {
			log.Fatalf("Invalid public key size. Must be %d bytes", ed25519.PublicKeySize)
		}
		pubKey = ed25519.PublicKey(pubKeyBytes)
		log.Printf("Loaded configured Ed25519 public key: %s", *pubKeyHex)
	} else {
		// Generate an ephemeral keypair for testing/development
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate ephemeral key pair: %v", err)
		}
		log.Printf("=== EPHEMERAL TESTING MODE ===")
		log.Printf("Generated Ed25519 Public Key (Hex):  %s", hex.EncodeToString(pubKey))
		log.Printf("Generated Ed25519 Private Key (Hex): %s", hex.EncodeToString(privKey))
		log.Printf("==============================")

		// Print QR Code connection info if appropriate
		relayURL := fmt.Sprintf("relay://%s#public_key=%s", *addr, hex.EncodeToString(pubKey))
		qr.PrintPairingQr(os.Stdout, relayURL)
	}

	server := NewRelayServer(*addr, pubKey)

	// Bind TCP Listener
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to start TCP listener on %s: %v", *addr, err)
	}
	server.listener = l
	log.Printf("Relay server listening on TCP %s", *addr)

	// Graceful Shutdown Channel
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down Relay server...")
		server.Close()
		os.Exit(0)
	}()

	// Accept Loop
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			// Check if listener is closed
			select {
			case <-sigChan:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		go server.handleConnection(conn)
	}
}

func (s *RelayServer) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.validator.Close()
}

func (s *RelayServer) handleConnection(conn net.Conn) {
	// Enforce initial timeout for reading the connection header
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	header, err := protocol.ReadHeader(conn)
	if err != nil {
		log.Printf("Failed to read header from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	// Clear deadlines for next steps
	_ = conn.SetReadDeadline(time.Time{})

	switch header.Opcode {
	case protocol.OpRegControl:
		s.handleRegisterControl(conn, header)
	case protocol.OpClientConn:
		s.handleClientConnection(conn, header)
	case protocol.OpRegData:
		s.handleRegisterData(conn, header)
	default:
		log.Printf("Unknown opcode %d from %s", header.Opcode, conn.RemoteAddr())
		conn.Close()
	}
}

func (s *RelayServer) handleRegisterControl(conn net.Conn, header *protocol.Header) {
	// 1. Verify token
	valid, err := s.validator.VerifyToken(header.Token, crypto.RoleControl, header.SessionID)
	if !valid || err != nil {
		log.Printf("Control registration failed for Session %s from %s: %v",
			hex.EncodeToString(header.SessionID[:]), conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	sessionID := header.SessionID
	log.Printf("Agent registered Control Channel for Session %s from %s",
		hex.EncodeToString(sessionID[:]), conn.RemoteAddr())

	// Store control stream (if an old stream exists, close it first)
	if old, loaded := s.controlStreams.Swap(sessionID, conn); loaded {
		if oldConn, ok := old.(net.Conn); ok {
			_ = oldConn.Close()
		}
	}

	// Monitor Control Stream for disconnect or keepalives
	go func() {
		defer func() {
			conn.Close()
			// Only delete from active registry if this exact connection is still registered
			if current, ok := s.controlStreams.Load(sessionID); ok && current == conn {
				s.controlStreams.Delete(sessionID)
				log.Printf("Control channel disconnected for Session %s", hex.EncodeToString(sessionID[:]))
			}
		}()

		buf := make([]byte, 1)
		for {
			// Set keep-alive/read deadline to detect silent drops (e.g. 1 minute)
			_ = conn.SetReadDeadline(time.Now().Add(65 * time.Second))
			_, err := conn.Read(buf)
			if err != nil {
				return // Disconnected
			}
		}
	}()
}

func (s *RelayServer) handleClientConnection(conn net.Conn, header *protocol.Header) {
	sessionID := header.SessionID

	// 1. Verify Client Token
	valid, err := s.validator.VerifyToken(header.Token, crypto.RoleClient, sessionID)
	if !valid || err != nil {
		log.Printf("Client authentication failed for Session %s from %s: %v",
			hex.EncodeToString(sessionID[:]), conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	// 2. Lookup Agent Control Connection
	ctrlVal, exists := s.controlStreams.Load(sessionID)
	if !exists {
		log.Printf("No active Agent Control Channel for Session %s requested by Client %s",
			hex.EncodeToString(sessionID[:]), conn.RemoteAddr())
		conn.Close()
		return
	}
	agentCtrlConn := ctrlVal.(net.Conn)

	// 3. Generate a secure, unique SplicingToken
	var splicingToken [32]byte
	if _, err := io.ReadFull(rand.Reader, splicingToken[:]); err != nil {
		log.Printf("Internal error generating splicing token: %v", err)
		conn.Close()
		return
	}

	// 4. Register client connection in waiting room
	matchChan := make(chan net.Conn, 1)
	s.waitingRoom.Store(splicingToken, matchChan)
	defer s.waitingRoom.Delete(splicingToken)

	// 5. Instruct the Agent to spawn a matching data connection
	log.Printf("Sending SPAWN_DATA_CHANNEL command to Agent for Session %s", hex.EncodeToString(sessionID[:]))
	cmd := &protocol.ControlMessage{
		Cmd:           protocol.CmdSpawnData,
		SplicingToken: splicingToken,
	}
	if err := protocol.WriteControlMessage(agentCtrlConn, cmd); err != nil {
		log.Printf("Failed to transmit spawn instruction to Agent: %v", err)
		conn.Close()
		return
	}

	// 6. Wait for Agent Data connection dialback (with 10-second timeout)
	select {
	case agentConn := <-matchChan:
		log.Printf("Matchmaking succeeded for Session %s! Initiating kernel space splice...", hex.EncodeToString(sessionID[:]))
		s.spliceConnections(conn, agentConn)
	case <-time.After(10 * time.Second):
		log.Printf("Matchmaking timeout for Session %s client %s", hex.EncodeToString(sessionID[:]), conn.RemoteAddr())
		conn.Close()
	}
}

func (s *RelayServer) handleRegisterData(conn net.Conn, header *protocol.Header) {
	token := header.SplicingToken

	// Look up matchmaking channel
	matchChanVal, exists := s.waitingRoom.Load(token)
	if !exists {
		log.Printf("Unknown or expired splicing token %s from %s", hex.EncodeToString(token[:]), conn.RemoteAddr())
		conn.Close()
		return
	}
	matchChan := matchChanVal.(chan net.Conn)

	// Hand connection over to waiting client
	select {
	case matchChan <- conn:
		// Succeeded handing over. Splicing loop will handle the rest.
	default:
		// Channel full/closed
		conn.Close()
	}
}

// spliceConnections pairs the Client and Agent connections and performs
// zero-copy kernel splicing using the optimized io.Copy path in Go.
func (s *RelayServer) spliceConnections(client, agent net.Conn) {
	// Unwrap connections to raw *net.TCPConn
	clientTCP, err1 := protocol.UnwrapTCP(client)
	agentTCP, err2 := protocol.UnwrapTCP(agent)

	if err1 != nil || err2 != nil {
		log.Printf("Splicing error: connections must be raw TCP (Client Err: %v, Agent Err: %v). Falling back to user-space copy...", err1, err2)
		// Fallback to standard bidirectional copy if unwrapping fails (e.g. mock net.Conn in tests)
		go s.bidirectionalCopy(client, agent)
		return
	}

	// Bidirectional Kernel Splice Loop
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer clientTCP.CloseWrite()
		defer agentTCP.CloseRead()
		// On Linux streams, io.Copy uses splice(2) system call internally
		_, _ = io.Copy(clientTCP, agentTCP)
	}()

	go func() {
		defer wg.Done()
		defer agentTCP.CloseWrite()
		defer clientTCP.CloseRead()
		// On Linux streams, io.Copy uses splice(2) system call internally
		_, _ = io.Copy(agentTCP, clientTCP)
	}()

	// Watch and close everything once transfer completes
	go func() {
		wg.Wait()
		client.Close()
		agent.Close()
		log.Printf("Session closed, resources completely reclaimed.")
	}()
}

// fallback copy loop for non-TCP or test mock environments
func (s *RelayServer) bidirectionalCopy(client, agent net.Conn) {
	defer client.Close()
	defer agent.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, agent)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(agent, client)
	}()

	wg.Wait()
	log.Printf("Session fallback closed, resources reclaimed.")
}
