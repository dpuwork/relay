package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Token layout constants
const (
	PayloadSize   = 25 // 8 bytes (ExpiresAt) + 1 byte (Role) + 16 bytes (SessionID)
	SignatureSize = 64 // Ed25519 signature is 64 bytes
	TokenSize     = PayloadSize + SignatureSize
)

// Roles defined in tokenomics
const (
	RoleControl uint8 = 0x01
	RoleClient  uint8 = 0x02
)

// TokenValidator manages replay protection and token validation
type TokenValidator struct {
	pubKey       ed25519.PublicKey
	spentTokens  sync.Map // key: [64]byte (signature), value: int64 (expiration timestamp)
	cleanupStop  chan struct{}
	cleanupMutex sync.Mutex
}

// NewTokenValidator creates a new TokenValidator with the given public key
func NewTokenValidator(pubKey ed25519.PublicKey) *TokenValidator {
	v := &TokenValidator{
		pubKey:      pubKey,
		cleanupStop: make(chan struct{}),
	}
	// Start background cleanup goroutine
	go v.startCleanupLoop(1 * time.Minute)
	return v
}

// Close stops the background cleanup loop
func (v *TokenValidator) Close() {
	v.cleanupMutex.Lock()
	defer v.cleanupMutex.Unlock()
	if v.cleanupStop != nil {
		close(v.cleanupStop)
		v.cleanupStop = nil
	}
}

// GenerateToken creates a signed, 89-byte binary token
func GenerateToken(sessionID [16]byte, role uint8, expiresAt int64, privKey ed25519.PrivateKey) []byte {
	payload := make([]byte, PayloadSize)
	binary.BigEndian.PutUint64(payload[0:8], uint64(expiresAt))
	payload[8] = role
	copy(payload[9:25], sessionID[:])

	signature := ed25519.Sign(privKey, payload)

	token := make([]byte, TokenSize)
	copy(token[0:PayloadSize], payload)
	copy(token[PayloadSize:TokenSize], signature)

	return token
}

// VerifyToken decodes, cryptographically verifies, and checks replay protection for a token
func (v *TokenValidator) VerifyToken(token []byte, expectedRole uint8, expectedSessionID [16]byte) (bool, error) {
	if len(token) != TokenSize {
		return false, errors.New("invalid token length")
	}

	payload := token[0:PayloadSize]
	signature := token[PayloadSize:TokenSize]

	// 1. Cryptographic Signature Verification
	if !ed25519.Verify(v.pubKey, payload, signature) {
		return false, errors.New("cryptographic signature mismatch")
	}

	// 2. Decode Payload
	expiresAt := int64(binary.BigEndian.Uint64(payload[0:8]))
	role := payload[8]
	var sessionID [16]byte
	copy(sessionID[:], payload[9:25])

	// 3. Time Validation (Expiration / Short-lived TTL Check)
	now := time.Now().Unix()
	if now >= expiresAt {
		return false, errors.New("token has expired")
	}

	// 4. Scope and Metadata Assertions
	if role != expectedRole {
		return false, errors.New("token role mismatch")
	}
	if sessionID != expectedSessionID {
		return false, errors.New("token session ID mismatch")
	}

	// 5. Replay Protection (Single-Use Token Enforcement)
	var sigKey [64]byte
	copy(sigKey[:], signature)

	if _, loaded := v.spentTokens.LoadOrStore(sigKey, expiresAt); loaded {
		return false, errors.New("token signature replay detected (single-use violated)")
	}

	return true, nil
}

// startCleanupLoop periodically removes expired signatures from the spentTokens map
func (v *TokenValidator) startCleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			v.spentTokens.Range(func(key, val interface{}) bool {
				expireTime, ok := val.(int64)
				if ok && now >= expireTime {
					v.spentTokens.Delete(key)
				}
				return true
			})
		case <-v.cleanupStop:
			return
		}
	}
}
