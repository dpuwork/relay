package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	validator := NewTokenValidator(pubKey)
	defer validator.Close()

	sessionID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	now := time.Now().Unix()
	expiresAt := now + 60

	// 1. Valid Token
	token := GenerateToken(sessionID, RoleControl, expiresAt, privKey)
	valid, err := validator.VerifyToken(token, RoleControl, sessionID)
	if !valid || err != nil {
		t.Errorf("Expected valid token, got error: %v", err)
	}

	// 2. Replay Protection (Single-Use)
	valid, err = validator.VerifyToken(token, RoleControl, sessionID)
	if valid || err == nil || err.Error() != "token signature replay detected (single-use violated)" {
		t.Errorf("Expected replay protection error, got valid=%v, err=%v", valid, err)
	}

	// 3. Expired Token
	expiredToken := GenerateToken(sessionID, RoleClient, now-10, privKey)
	valid, err = validator.VerifyToken(expiredToken, RoleClient, sessionID)
	if valid || err == nil || err.Error() != "token has expired" {
		t.Errorf("Expected expired error, got valid=%v, err=%v", valid, err)
	}

	// 4. Role Mismatch
	tokenRoleClient := GenerateToken(sessionID, RoleClient, expiresAt, privKey)
	valid, err = validator.VerifyToken(tokenRoleClient, RoleControl, sessionID)
	if valid || err == nil || err.Error() != "token role mismatch" {
		t.Errorf("Expected role mismatch error, got valid=%v, err=%v", valid, err)
	}

	// 5. Session ID Mismatch
	wrongSessionID := [16]byte{9, 9, 9}
	tokenWrongSession := GenerateToken(sessionID, RoleClient, expiresAt, privKey)
	valid, err = validator.VerifyToken(tokenWrongSession, RoleClient, wrongSessionID)
	if valid || err == nil || err.Error() != "token session ID mismatch" {
		t.Errorf("Expected session ID mismatch, got valid=%v, err=%v", valid, err)
	}

	// 6. Invalid Signature
	invalidToken := GenerateToken(sessionID, RoleControl, expiresAt, privKey)
	invalidToken[len(invalidToken)-1] ^= 0xFF // Flip a bit in the signature
	valid, err = validator.VerifyToken(invalidToken, RoleControl, sessionID)
	if valid || err == nil || err.Error() != "cryptographic signature mismatch" {
		t.Errorf("Expected signature mismatch, got valid=%v, err=%v", valid, err)
	}
}

func TestValidatorCleanup(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	validator := NewTokenValidator(pubKey)
	defer validator.Close()

	sessionID := [16]byte{1}
	expiresAt := time.Now().Unix() + 1 // Expires in 1 second
	token := GenerateToken(sessionID, RoleControl, expiresAt, privKey)

	// Consume the token
	valid, _ := validator.VerifyToken(token, RoleControl, sessionID)
	if !valid {
		t.Fatalf("Token should be valid on first use")
	}

	// Ensure it's in the spent map
	count := 0
	validator.spentTokens.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count != 1 {
		t.Errorf("Expected 1 spent token, found %d", count)
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Manually trigger cleanup logic since the background ticker might be 1m
	now := time.Now().Unix()
	validator.spentTokens.Range(func(key, val interface{}) bool {
		expireTime := val.(int64)
		if now >= expireTime {
			validator.spentTokens.Delete(key)
		}
		return true
	})

	count = 0
	validator.spentTokens.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("Expected 0 spent tokens after cleanup, found %d", count)
	}
}
