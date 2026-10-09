package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

type PasswordHasher struct {
	bcryptCost int
}

func main() {
	hasher := NewPasswordHasher(0)
	reader := bufio.NewReader(os.Stdin)

	readInput := func(prompt string) (string, bool) {
		fmt.Print(prompt)
		text, err := reader.ReadString('\n')
		if err != nil && !(err == io.EOF && len(text) > 0) {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Read input: %v\n", err)
			}
			return "", false
		}
		return strings.TrimSuffix(strings.TrimSuffix(text, "\n"), "\r"), true
	}

	for {
		fmt.Println("\n1. Hash a string\n2. Verify a hash\n0. Exit")
		choice, ok := readInput("Choose an option: ")
		if !ok {
			return
		}
		choice = strings.TrimSpace(choice)
		switch choice {
		case "0":
			return
		case "1", "2":
		default:
			fmt.Println("Invalid option. Choose 1, 2, or 0.")
			continue
		}

		plain, ok := readInput("Enter plain text: ")
		if !ok {
			return
		}
		if choice == "1" {
			argon2Hash, bcryptHash, err := hasher.Hash(plain)
			if err != nil {
				fmt.Printf("Hashing failed: %v\n", err)
				continue
			}
			fmt.Printf("argon2 hash: %s\n", argon2Hash)
			fmt.Printf("bcrypt hash (Base64): %s\n", bcryptHash)
			continue
		}

		hashed, ok := readInput("Enter hash (Argon2 or bcrypt): ")
		if !ok {
			return
		}
		if err := hasher.Verify(plain, strings.TrimSpace(hashed)); err != nil {
			fmt.Printf("Verification failed: %v\n", err)
			continue
		}
		fmt.Println("Verification successful: the hash matches the plain text.")
	}
}

func NewPasswordHasher(cost int) *PasswordHasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasher{bcryptCost: cost}
}

func (h *PasswordHasher) Hash(plain string) (string, string, error) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plain), h.bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("generate bcrypt hash: %w", err)
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), base64.StdEncoding.EncodeToString(bcryptHash), nil
}

func (h *PasswordHasher) Verify(plain, hashed string) error {
	if strings.HasPrefix(hashed, "$argon2id$") {
		return h.verifyArgon2id(plain, hashed)
	}
	if !strings.HasPrefix(hashed, "$") {
		decoded, err := base64.StdEncoding.DecodeString(hashed)
		if err != nil {
			return fmt.Errorf("decode bcrypt hash: %w", err)
		}
		hashed = string(decoded)
	}
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}

func (h *PasswordHasher) NeedsUpgrade(hashed string) bool {
	return !strings.HasPrefix(hashed, "$argon2id$")
}

func (h *PasswordHasher) verifyArgon2id(plain, hashed string) error {
	parts := strings.Split(hashed, "$")
	// expected: ["", "argon2id", "v=N", "m=N,t=N,p=N", "<salt>", "<key>"]
	if len(parts) != 6 {
		return fmt.Errorf("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("parse argon2id version: %w", err)
	}
	if version != argon2.Version {
		return fmt.Errorf("unsupported argon2id version: %d", version)
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("parse argon2id params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("decode argon2id salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("decode argon2id key: %w", err)
	}
	if len(key) != argon2KeyLen {
		return fmt.Errorf("unexpected argon2id key length: %d", len(key))
	}

	candidate := argon2.IDKey([]byte(plain), salt, time, memory, threads, argon2KeyLen)
	if subtle.ConstantTimeCompare(candidate, key) != 1 {
		return fmt.Errorf("password mismatch")
	}
	return nil
}
