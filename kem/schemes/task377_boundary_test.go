package schemes_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

func task377ImplicitRejection(name string) bool {
	switch name {
	case "FrodoKEM-640-SHAKE",
		"Kyber512", "Kyber768", "Kyber1024",
		"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"X-Wing":
		return true
	default:
		return false
	}
}

func TestTask377CiphertextSizeBoundary(t *testing.T) {
	for _, sch := range schemes.All() {
		t.Run(sch.Name(), func(t *testing.T) {
			_, sk, err := sch.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}

			ctSize := sch.CiphertextSize()
			for n := 0; n <= ctSize+1; n++ {
				if n == ctSize {
					continue
				}

				ss, err := sch.Decapsulate(sk, make([]byte, n))
				if err == nil {
					t.Fatalf("length %d: expected size error", n)
				}
				if !errors.Is(err, kem.ErrCiphertextSize) {
					t.Fatalf("length %d: error is %v, want %v", n, err, kem.ErrCiphertextSize)
				}
				if ss != nil {
					t.Fatalf("length %d: returned secret with error", n)
				}
			}
		})
	}
}

func TestTask377MalformedCiphertextContract(t *testing.T) {
	for _, sch := range schemes.All() {
		t.Run(sch.Name(), func(t *testing.T) {
			pk, sk, err := sch.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			ct, wantSS, err := sch.Encapsulate(pk)
			if err != nil {
				t.Fatal(err)
			}
			gotSS, err := sch.Decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("valid ciphertext: %v", err)
			}
			if !bytes.Equal(gotSS, wantSS) {
				t.Fatal("valid ciphertext changed shared secret")
			}

			variants := task377MalformedVariants(sch.Name(), ct)
			for i, badCT := range variants {
				ss, err := sch.Decapsulate(sk, badCT)
				if err != nil {
					if ss != nil {
						t.Fatalf("variant %d: secret returned with error", i)
					}
					if task377ImplicitRejection(sch.Name()) {
						t.Fatalf("variant %d: implicit rejection scheme returned error: %v", i, err)
					}
					continue
				}

				if len(ss) != sch.SharedKeySize() {
					t.Fatalf("variant %d: secret length %d, want %d", i, len(ss), sch.SharedKeySize())
				}

				again, err := sch.Decapsulate(sk, badCT)
				if err != nil {
					t.Fatalf("variant %d: second decapsulation: %v", i, err)
				}
				if !bytes.Equal(ss, again) {
					t.Fatalf("variant %d: non-deterministic implicit rejection", i)
				}
			}
		})
	}
}

func task377MalformedVariants(name string, ct []byte) [][]byte {
	zero := make([]byte, len(ct))
	full := bytes.Repeat([]byte{0xff}, len(ct))
	variants := [][]byte{zero, full}

	for i := 0; i < 8; i++ {
		bad := append([]byte(nil), ct...)
		seed := []byte(fmt.Sprintf("%s/%d", name, i))
		for j := range bad {
			bad[j] ^= seed[j%len(seed)]
			if j%(i+3) == 0 {
				bad[j] = byte((j*31 + i*7) & 0xff)
			}
		}
		variants = append(variants, bad)
	}
	return variants
}
