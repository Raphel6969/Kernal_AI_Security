package auth_test

import (
	"testing"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/auth"
)

func TestHashAndVerifyPassword(t *testing.T) {
	plain := "super-secret-password-123"

	hash, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty hash")
	}
	if hash == plain {
		t.Fatal("Hash must not equal plaintext")
	}

	// Correct password should verify
	if !auth.CheckPasswordHash(plain, hash) {
		t.Error("CheckPasswordHash returned false for correct password")
	}

	// Wrong password must not verify
	if auth.CheckPasswordHash("wrong-password", hash) {
		t.Error("CheckPasswordHash returned true for wrong password")
	}
}

func TestHashDifferentEachTime(t *testing.T) {
	plain := "same-password"
	hash1, _ := auth.HashPassword(plain)
	hash2, _ := auth.HashPassword(plain)

	// bcrypt salts each hash, so they must differ
	if hash1 == hash2 {
		t.Error("Two hashes of the same password should be different (bcrypt salt)")
	}

	// Both must still verify correctly
	if !auth.CheckPasswordHash(plain, hash1) || !auth.CheckPasswordHash(plain, hash2) {
		t.Error("Both hashes should verify against the original plaintext")
	}
}
