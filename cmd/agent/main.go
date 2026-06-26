package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"relay/pkg/protocol"
)

type Agent struct {
	relayAddr  string
	localAddr  string
	sessionID  [16]byte
	token      []byte
	ctrlConn   net.Conn
	stopChan   chan struct{}
	wg         sync.WaitGroup
	connMutex  sync.Mutex
	isShutdown bool
}

func NewAgent(relayAddr, localAddr string, sessionID [16]byte, token []byte) *Agent {
	return &Agent{
		relayAddr: relayAddr,
		localAddr: localAddr,
		sessionID: sessionID,
		token:     token,
		stopChan:  make(chan struct{}),
	}
}

func main() {
	relayAddr := flag.String("relay", "127.0.0.1:9090", "TCP address of the Relay server")
	localAddr := flag.String("local", "127.0.0.1:8080", "TCP address of the local target service")
	sessionHex := flag.String("session", "", "Hex-encoded 16-byte Session ID")
	tokenHex := flag.String("token", "", "Hex-encoded registration token")
	flag.Parse()

	if *sessionHex == "" || *tokenHex == "" {
		log.Println("Error: both -session and -token flags are required to run the agent stand-alone.")
		flag.Usage()
		os.Exit(1)
	}

	sessionBytes, err := hex.DecodeString(*sessionHex)
	if err != nil || len(sessionBytes) != 16 {
		log.Fatalf("Invalid -session. Must be a 16-byte hex string: %v", err)
	}

	tokenBytes, err := hex.DecodeString(*tokenHex)
	if err != nil {
		log.Fatalf("Invalid -token. Must be a hex string: %v", err)
	}

	var sessionID [16]byte
	copy(sessionID[:], sessionBytes)

	agent := NewAgent(*relayAddr, *localAddr, sessionID, tokenBytes)

	// Intercept shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down Agent...")
		agent.Close()
		os.Exit(0)
	}()

	// Start Agent Core
	agent.Start()
}

func (a *Agent) Start() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-a.stopChan:
			return
		default:
		}

		log.Printf("Agent dialing outbound to Relay control endpoint %s...", a.relayAddr)
		err := a.connectAndRun()
		if err != nil {
			a.connMutex.Lock()
			shutdown := a.isShutdown
			a.connMutex.Unlock()

			if shutdown {
				return
			}

			log.Printf("Connection error: %v. Reconnecting in %v...", err, backoff)
			select {
			case <-a.stopChan:
				return
			case <-time.After(backoff):
			}

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Reset backoff on successful run
			backoff = 1 * time.Second
		}
	}
}

func (a *Agent) Close() {
	a.connMutex.Lock()
	a.isShutdown = true
	if a.ctrlConn != nil {
		a.ctrlConn.Close()
	}
	a.connMutex.Unlock()

	close(a.stopChan)
	a.wg.Wait()
	log.Println("Agent stopped completely.")
}

func (a *Agent) connectAndRun() error {
	conn, err := net.DialTimeout("tcp", a.relayAddr, 10*time.Second)
	if err != nil {
		return err
	}

	a.connMutex.Lock()
	if a.isShutdown {
		conn.Close()
		a.connMutex.Unlock()
		return nil
	}
	a.ctrlConn = conn
	a.connMutex.Unlock()

	defer func() {
		a.connMutex.Lock()
		conn.Close()
		if a.ctrlConn == conn {
			a.ctrlConn = nil
		}
		a.connMutex.Unlock()
	}()

	// 1. Send Control Registration Header
	header := &protocol.Header{
		Opcode:    protocol.OpRegControl,
		SessionID: a.sessionID,
		Token:     a.token,
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteHeader(conn, header); err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Time{})

	log.Printf("Successfully registered Agent Control Channel for Session %s", hex.EncodeToString(a.sessionID[:]))

	// Start keepalive heartbeat generator
	go a.heartbeatLoop(conn)

	// 2. Read and handle commands from the Relay Server
	for {
		cmd, err := protocol.ReadControlMessage(conn)
		if err != nil {
			return err
		}

		if cmd.Cmd == protocol.CmdSpawnData {
			log.Printf("Received instruction to spawn data tunnel with token: %s", hex.EncodeToString(cmd.SplicingToken[:]))
			a.wg.Add(1)
			go func(token [32]byte) {
				defer a.wg.Done()
				a.handleSpawnData(token)
			}(cmd.SplicingToken)
		}
	}
}

func (a *Agent) heartbeatLoop(conn net.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Write a simple empty payload byte as a TCP level heartbeat
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write([]byte{0x00})
			if err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Time{})
		case <-a.stopChan:
			return
		}
	}
}

func (a *Agent) handleSpawnData(splicingToken [32]byte) {
	log.Printf("Connecting to local host target %s...", a.localAddr)
	localConn, err := net.DialTimeout("tcp", a.localAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to local target %s: %v", a.localAddr, err)
		return
	}
	defer localConn.Close()

	log.Printf("Connecting data socket to Relay %s...", a.relayAddr)
	relayConn, err := net.DialTimeout("tcp", a.relayAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect data socket to Relay: %v", err)
		return
	}
	defer relayConn.Close()

	// Send Register Data header
	header := &protocol.Header{
		Opcode:        protocol.OpRegData,
		SessionID:     a.sessionID,
		SplicingToken: splicingToken,
	}

	_ = relayConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteHeader(relayConn, header); err != nil {
		log.Printf("Failed to write data header to Relay: %v", err)
		return
	}
	_ = relayConn.SetWriteDeadline(time.Time{})

	log.Printf("Tunnel linked! Splicing local target %s <-> Relay data plane", a.localAddr)

	// Bidirectional tunnel bridge (using io.Copy which calls splice(2) on Linux)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, relayConn)
		_ = localConn.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(relayConn, localConn)
		_ = relayConn.Close()
	}()

	wg.Wait()
	log.Printf("Data tunnel closed for token %s", hex.EncodeToString(splicingToken[:]))
}
