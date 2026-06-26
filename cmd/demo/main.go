package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"relay/pkg/crypto"
	"relay/pkg/protocol"
	"relay/pkg/qr"
)

func main() {
	log.Println("=== STARTING END-TO-END ZERO-COPY TCP RELAY DEMO ===")

	// 1. Generate Ed25519 keypair for authentication
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	log.Printf("[Crypto] Generated Ed25519 trust anchor. Public Key: %s", hex.EncodeToString(pubKey))

	// 2. Start mock local target service (e.g. an echo server with a custom banner)
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to bind mock target: %v", err)
	}
	localAddr := targetListener.Addr().String()
	log.Printf("[Target] Mock local target listening on %s", localAddr)

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					// Echo back with a custom tag
					_, _ = c.Write([]byte(fmt.Sprintf("[ECHO-TARGET] -> %s", line)))
				}
			}(conn)
		}
	}()
	defer targetListener.Close()

	// 3. Start Relay Server in-process on a random local port
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to bind Relay listener: %v", err)
	}
	relayAddr := relayListener.Addr().String()
	log.Printf("[Relay] Server listening on %s", relayAddr)

	// We'll manually create the server structure and route connections
	validator := crypto.NewTokenValidator(pubKey)
	defer validator.Close()

	var controlStreams sync.Map
	var waitingRoom sync.Map

	go func() {
		for {
			conn, err := relayListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// We call ReadHeader
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				header, err := protocol.ReadHeader(c)
				if err != nil {
					c.Close()
					return
				}
				_ = c.SetReadDeadline(time.Time{})

				switch header.Opcode {
				case protocol.OpRegControl:
					valid, err := validator.VerifyToken(header.Token, crypto.RoleControl, header.SessionID)
					if !valid || err != nil {
						log.Printf("[Relay] Control token verification failed: %v", err)
						c.Close()
						return
					}
					sessionID := header.SessionID
					log.Printf("[Relay] Registered control channel for session %s", hex.EncodeToString(sessionID[:]))
					controlStreams.Store(sessionID, c)

				case protocol.OpClientConn:
					valid, err := validator.VerifyToken(header.Token, crypto.RoleClient, header.SessionID)
					if !valid || err != nil {
						log.Printf("[Relay] Client token verification failed: %v", err)
						c.Close()
						return
					}
					sessionID := header.SessionID
					ctrlVal, exists := controlStreams.Load(sessionID)
					if !exists {
						log.Printf("[Relay] No control channel for session %s", hex.EncodeToString(sessionID[:]))
						c.Close()
						return
					}
					agentCtrlConn := ctrlVal.(net.Conn)

					// Matchmaking
					var splicingToken [32]byte
					_, _ = io.ReadFull(rand.Reader, splicingToken[:])

					matchChan := make(chan net.Conn, 1)
					waitingRoom.Store(splicingToken, matchChan)
					defer waitingRoom.Delete(splicingToken)

					// Ask agent to connect back
					cmd := &protocol.ControlMessage{
						Cmd:           protocol.CmdSpawnData,
						SplicingToken: splicingToken,
					}
					_ = protocol.WriteControlMessage(agentCtrlConn, cmd)

					select {
					case agentConn := <-matchChan:
						log.Println("[Relay] Matchmaking success! Splicing sockets...")
						// Splicing
						var wg sync.WaitGroup
						wg.Add(2)
						go func() {
							defer wg.Done()
							_, _ = io.Copy(c, agentConn)
							c.Close()
						}()
						go func() {
							defer wg.Done()
							_, _ = io.Copy(agentConn, c)
							agentConn.Close()
						}()
						wg.Wait()
					case <-time.After(5 * time.Second):
						log.Println("[Relay] Matchmaking timeout")
						c.Close()
					}

				case protocol.OpRegData:
					token := header.SplicingToken
					matchChanVal, exists := waitingRoom.Load(token)
					if !exists {
						c.Close()
						return
					}
					matchChan := matchChanVal.(chan net.Conn)
					matchChan <- c
				}
			}(conn)
		}
	}()
	defer relayListener.Close()

	// 4. Generate high-entropy Session ID and tokens
	var sessionID [16]byte
	_, _ = io.ReadFull(rand.Reader, sessionID[:])
	sessionHex := hex.EncodeToString(sessionID[:])
	log.Printf("[Demo] Initiated Session ID: %s", sessionHex)

	now := time.Now().Unix()
	expiresAt := now + 300 // 5-minute TTL

	agentToken := crypto.GenerateToken(sessionID, crypto.RoleControl, expiresAt, privKey)
	clientToken := crypto.GenerateToken(sessionID, crypto.RoleClient, expiresAt, privKey)

	// Print connection QR Code for Client pairing
	relayClientURL := fmt.Sprintf("relay://%s#session=%s&token=%s", relayAddr, sessionHex, hex.EncodeToString(clientToken))
	qr.PrintPairingQr(os.Stdout, relayClientURL)

	// 5. Connect and start Agent
	log.Println("[Agent] Starting background Agent...")
	agentCtrlConn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		log.Fatalf("Agent failed to dial relay control port: %v", err)
	}

	// Register Agent Control channel
	agentRegHeader := &protocol.Header{
		Opcode:    protocol.OpRegControl,
		SessionID: sessionID,
		Token:     agentToken,
	}
	err = protocol.WriteHeader(agentCtrlConn, agentRegHeader)
	if err != nil {
		log.Fatalf("Agent failed to write registration header: %v", err)
	}
	log.Println("[Agent] Sent registration control header")

	// Start Agent Control Loop
	go func() {
		defer agentCtrlConn.Close()
		for {
			cmd, err := protocol.ReadControlMessage(agentCtrlConn)
			if err != nil {
				return
			}
			if cmd.Cmd == protocol.CmdSpawnData {
				log.Printf("[Agent] Spawning data tunnel for token: %s", hex.EncodeToString(cmd.SplicingToken[:]))
				// Dial local target
				localConn, err := net.Dial("tcp", localAddr)
				if err != nil {
					log.Printf("[Agent] Failed to dial mock target: %v", err)
					return
				}
				// Dial relay data port
				relayDataConn, err := net.Dial("tcp", relayAddr)
				if err != nil {
					localConn.Close()
					log.Printf("[Agent] Failed to dial relay data port: %v", err)
					return
				}
				// Write OpRegData header
				dataHeader := &protocol.Header{
					Opcode:        protocol.OpRegData,
					SessionID:     sessionID,
					SplicingToken: cmd.SplicingToken,
				}
				_ = protocol.WriteHeader(relayDataConn, dataHeader)

				// Pipe data bidirectionally
				go func() {
					defer localConn.Close()
					defer relayDataConn.Close()
					_, _ = io.Copy(localConn, relayDataConn)
				}()
				go func() {
					defer localConn.Close()
					defer relayDataConn.Close()
					_, _ = io.Copy(relayDataConn, localConn)
				}()
			}
		}
	}()

	// Allow connection to establish
	time.Sleep(500 * time.Millisecond)

	// 6. Connect as a Client to the Relay
	log.Println("[Client] Dialing Relay connection...")
	clientConn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		log.Fatalf("Client failed to dial relay: %v", err)
	}
	defer clientConn.Close()

	// Send Client Connection header
	clientHeader := &protocol.Header{
		Opcode:    protocol.OpClientConn,
		SessionID: sessionID,
		Token:     clientToken,
	}
	err = protocol.WriteHeader(clientConn, clientHeader)
	if err != nil {
		log.Fatalf("Client failed to send header: %v", err)
	}
	log.Println("[Client] Sent handshake, waiting for matchmaking...")

	// 7. Test Transmission & Verification
	payload := "Testing the high-performance zero-copy relay pipeline!\n"
	log.Printf("[Client] Transmitting: %q", payload)
	_, err = clientConn.Write([]byte(payload))
	if err != nil {
		log.Fatalf("Client failed to write: %v", err)
	}

	// Read response from Relay
	replyReader := bufio.NewReader(clientConn)
	response, err := replyReader.ReadString('\n')
	if err != nil {
		log.Fatalf("Client failed to read response: %v", err)
	}
	log.Printf("[Client] Received response: %q", response)

	expectedResponse := fmt.Sprintf("[ECHO-TARGET] -> %s", payload)
	if response != expectedResponse {
		log.Fatalf("Error: verification mismatch!\nExpected: %q\nReceived: %q", expectedResponse, response)
	}

	log.Println("====================================================")
	log.Println(" SUCCESS: End-to-end integration test verified!")
	log.Println("====================================================")
}
