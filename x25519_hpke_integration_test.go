package circl_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

// RFC 7748, section 6.1.
const (
	rfc7748AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPrivate   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748BobPublic    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748Shared       = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

var errIntegrationPeerKeyRejected = errors.New("integration test: peer key rejected")

// Canonical low-order points rejected by x25519.Shared. They are duplicated
// here so the integration boundary does not depend on package internals.
var rejectedX25519Points = []struct {
	name string
	hex  string
}{
	{"order-2", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"order-4", "0100000000000000000000000000000000000000000000000000000000000000"},
	{
		"order-8-a",
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	},
	{
		"order-8-b",
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	},
	{
		"twist-order-4",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	},
}

type keyEncoding struct {
	name  string
	bytes []byte
}

type hpkeBoundary struct {
	scheme   kem.Scheme
	auth     kem.AuthScheme
	suite    hpke.Suite
	skR      kem.PrivateKey
	skS      kem.PrivateKey
	seed     []byte
	validEnc []byte
}

func decodeHexKey(t *testing.T, s string) x25519.Key {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != x25519.Size {
		t.Fatalf("got %d bytes, want %d", len(raw), x25519.Size)
	}
	var k x25519.Key
	copy(k[:], raw)
	return k
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func leBytesToBigInt(b []byte) *big.Int {
	be := bytes.Clone(b)
	for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return new(big.Int).SetBytes(be)
}

func bigIntToLE32(t *testing.T, x *big.Int) []byte {
	t.Helper()
	if x.Sign() < 0 {
		t.Fatal("cannot encode a negative field element")
	}
	be := x.Bytes()
	if len(be) > x25519.Size {
		t.Fatalf("field element is %d bytes, want at most %d", len(be), x25519.Size)
	}
	out := make([]byte, x25519.Size)
	copy(out[x25519.Size-len(be):], be)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// equivalentX25519Encodings returns wire encodings decoded as the same field
// element. Bit 255 is ignored by X25519 decoding, and integers are reduced
// modulo 2^255-19.
func equivalentX25519Encodings(t *testing.T, canonical string) []keyEncoding {
	t.Helper()
	raw := hexBytes(t, canonical)
	x := leBytesToBigInt(raw)
	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	modulus := new(big.Int).Sub(two255, big.NewInt(19))

	encodings := []keyEncoding{
		{"canonical", bytes.Clone(raw)},
		{"ignored-high-bit", bigIntToLE32(t, new(big.Int).Add(x, two255))},
	}

	// x+p is another decoded representative only when it is below 2^255;
	// otherwise the ignored high bit changes the decoded value first.
	nonCanonical := new(big.Int).Add(x, modulus)
	if nonCanonical.Cmp(two255) < 0 {
		encodings = append(encodings,
			keyEncoding{"mod-p-alias", bigIntToLE32(t, nonCanonical)},
			keyEncoding{
				"mod-p-alias-ignored-high-bit",
				bigIntToLE32(t, new(big.Int).Add(nonCanonical, two255)),
			},
		)
	}

	return encodings
}

// deriveCheckedX25519Key is the safe integration pattern: the boolean result
// of x25519.Shared must be checked before the shared secret reaches the KDF.
func deriveCheckedX25519Key(secret *x25519.Key, peer []byte) ([]byte, error) {
	if len(peer) != x25519.Size {
		return nil, fmt.Errorf("%w: length %d", errIntegrationPeerKeyRejected, len(peer))
	}

	var pk, ss x25519.Key
	copy(pk[:], peer)
	if !x25519.Shared(&ss, secret, &pk) {
		return nil, errIntegrationPeerKeyRejected
	}

	material := hkdf.New(sha256.New, ss[:], nil, []byte("circl/integration/x25519-key"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(material, key); err != nil {
		return nil, err
	}
	return key, nil
}

func assertDirectRejected(t *testing.T, secret *x25519.Key, encoding keyEncoding) {
	t.Helper()

	var pk, ss x25519.Key
	copy(pk[:], encoding.bytes)
	if x25519.Shared(&ss, secret, &pk) {
		t.Errorf("%s: x25519.Shared accepted invalid point", encoding.name)
	}
	if ss != (x25519.Key{}) {
		t.Errorf("%s: rejected point produced nonzero shared secret", encoding.name)
	}

	key, err := deriveCheckedX25519Key(secret, encoding.bytes)
	if !errors.Is(err, errIntegrationPeerKeyRejected) {
		t.Errorf("%s: key derivation error = %v, want %v",
			encoding.name, err, errIntegrationPeerKeyRejected)
	}
	if key != nil {
		t.Errorf("%s: rejected point produced a consumable key", encoding.name)
	}
}

func newHPKEBoundary(t *testing.T) *hpkeBoundary {
	t.Helper()

	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	auth, ok := scheme.(kem.AuthScheme)
	if !ok {
		t.Fatal("X25519 HPKE KEM does not implement AuthScheme")
	}
	suite := hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_ChaCha20Poly1305,
	)

	receiverSeed := bytes.Repeat([]byte{'R'}, scheme.SeedSize())
	senderSeed := bytes.Repeat([]byte{'S'}, scheme.SeedSize())
	_, skR := scheme.DeriveKeyPair(receiverSeed)
	_, skS := scheme.DeriveKeyPair(senderSeed)

	seed := bytes.Repeat([]byte{'E'}, scheme.EncapsulationSeedSize())
	validEnc, validSS, err := scheme.EncapsulateDeterministically(skR.Public(), seed)
	if err != nil {
		t.Fatalf("create valid encapsulation: %v", err)
	}
	gotSS, err := scheme.Decapsulate(skR, validEnc)
	if err != nil {
		t.Fatalf("decapsulate valid encapsulation: %v", err)
	}
	if !bytes.Equal(gotSS, validSS) {
		t.Fatal("valid KEM session did not round-trip")
	}

	return &hpkeBoundary{
		scheme:   scheme,
		auth:     auth,
		suite:    suite,
		skR:      skR,
		skS:      skS,
		seed:     seed,
		validEnc: validEnc,
	}
}

func assertHPKEError(t *testing.T, err error, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded for invalid X25519 point", context)
	}
	if !errors.Is(err, hpke.ErrInvalidKEMSharedSecret) {
		t.Fatalf("%s error = %v, want %v", context, err, hpke.ErrInvalidKEMSharedSecret)
	}
}

func assertHPKEPeerKeyRejected(t *testing.T, env *hpkeBoundary, peer []byte) {
	t.Helper()

	pk, err := env.scheme.UnmarshalBinaryPublicKey(peer)
	if err != nil {
		// Rejection during parsing is the same security boundary at an earlier
		// API point; there is no key object that can reach setup or a KDF.
		return
	}

	ct, ss, err := env.scheme.EncapsulateDeterministically(pk, env.seed)
	assertHPKEError(t, err, "EncapsulateDeterministically")
	if ct != nil || ss != nil {
		t.Error("EncapsulateDeterministically returned key material after failure")
	}

	authCT, authSS, err := env.auth.AuthEncapsulateDeterministically(
		pk, env.skS, env.seed,
	)
	assertHPKEError(t, err, "AuthEncapsulateDeterministically")
	if authCT != nil || authSS != nil {
		t.Error("AuthEncapsulateDeterministically returned key material after failure")
	}

	sender, err := env.suite.NewSender(pk, []byte("integration-info"))
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	enc, sealer, err := sender.Setup(bytes.NewReader(env.seed))
	assertHPKEError(t, err, "Sender.Setup")
	if enc != nil || sealer != nil {
		t.Error("Sender.Setup returned a successful context after failure")
	}

	ss, err = env.scheme.Decapsulate(env.skR, peer)
	assertHPKEError(t, err, "Decapsulate")
	if ss != nil {
		t.Error("Decapsulate returned key material after failure")
	}

	authSS, err = env.auth.AuthDecapsulate(env.skR, env.validEnc, pk)
	assertHPKEError(t, err, "AuthDecapsulate")
	if authSS != nil {
		t.Error("AuthDecapsulate returned key material after failure")
	}

	receiver, err := env.suite.NewReceiver(env.skR, []byte("integration-info"))
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	opener, err := receiver.Setup(peer)
	assertHPKEError(t, err, "Receiver.Setup")
	if opener != nil {
		t.Error("Receiver.Setup returned a successful context after failure")
	}

	authReceiver, err := env.suite.NewReceiver(env.skR, []byte("integration-info"))
	if err != nil {
		t.Fatalf("NewReceiver for auth: %v", err)
	}
	authOpener, err := authReceiver.SetupAuth(env.validEnc, pk)
	assertHPKEError(t, err, "Receiver.SetupAuth")
	if authOpener != nil {
		t.Error("Receiver.SetupAuth returned a successful context after failure")
	}

	assertHPKEPSKModesRejected(t, env, pk, peer)
}

func assertHPKEPSKModesRejected(
	t *testing.T,
	env *hpkeBoundary,
	pk kem.PublicKey,
	peer []byte,
) {
	t.Helper()
	psk := []byte("integration-psk")
	pskID := []byte("integration-psk-id")

	pskSender, err := env.suite.NewSender(pk, []byte("integration-info"))
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := pskSender.SetupPSK(bytes.NewReader(env.seed), psk, pskID)
	assertHPKEError(t, err, "Sender.SetupPSK")
	if enc != nil || sealer != nil {
		t.Error("Sender.SetupPSK returned a successful context after failure")
	}

	authPSKSender, err := env.suite.NewSender(pk, []byte("integration-info"))
	if err != nil {
		t.Fatal(err)
	}
	authEnc, authSealer, err := authPSKSender.SetupAuthPSK(
		bytes.NewReader(env.seed), env.skS, psk, pskID,
	)
	assertHPKEError(t, err, "Sender.SetupAuthPSK")
	if authEnc != nil || authSealer != nil {
		t.Error("Sender.SetupAuthPSK returned a successful context after failure")
	}

	pskReceiver, err := env.suite.NewReceiver(env.skR, []byte("integration-info"))
	if err != nil {
		t.Fatal(err)
	}
	opener, err := pskReceiver.SetupPSK(peer, psk, pskID)
	assertHPKEError(t, err, "Receiver.SetupPSK")
	if opener != nil {
		t.Error("Receiver.SetupPSK returned a successful context after failure")
	}

	authPSKReceiver, err := env.suite.NewReceiver(env.skR, []byte("integration-info"))
	if err != nil {
		t.Fatal(err)
	}
	authOpener, err := authPSKReceiver.SetupAuthPSK(
		env.validEnc, psk, pskID, pk,
	)
	assertHPKEError(t, err, "Receiver.SetupAuthPSK")
	if authOpener != nil {
		t.Error("Receiver.SetupAuthPSK returned a successful context after failure")
	}
}

func TestX25519InvalidPeerKeysRejectedAtBothBoundaries(t *testing.T) {
	secret := decodeHexKey(t, rfc7748AlicePrivate)
	env := newHPKEBoundary(t)

	for _, point := range rejectedX25519Points {
		encodings := equivalentX25519Encodings(t, point.hex)
		for _, encoding := range encodings {
			name := fmt.Sprintf("%s/%s", point.name, encoding.name)
			t.Run(name, func(t *testing.T) {
				assertDirectRejected(t, &secret, encoding)
				assertHPKEPeerKeyRejected(t, env, encoding.bytes)
			})
		}
	}
}

func TestX25519ValidVectorRepresentationsRemainAccepted(t *testing.T) {
	secret := decodeHexKey(t, rfc7748AlicePrivate)
	want := decodeHexKey(t, rfc7748Shared)

	for _, encoding := range equivalentX25519Encodings(t, rfc7748BobPublic) {
		t.Run(encoding.name, func(t *testing.T) {
			var pk, got x25519.Key
			copy(pk[:], encoding.bytes)
			if !x25519.Shared(&got, &secret, &pk) {
				t.Fatal("valid point representation was rejected")
			}
			if got != want {
				t.Fatalf("shared secret changed for representation %s", encoding.name)
			}

			key, err := deriveCheckedX25519Key(&secret, encoding.bytes)
			if err != nil {
				t.Fatalf("checked derivation failed: %v", err)
			}
			if len(key) != 32 {
				t.Fatalf("derived key length = %d, want 32", len(key))
			}
		})
	}
}

func TestX25519GeneratedRepresentationsRemainAccepted(t *testing.T) {
	for range 16 {
		var secret, canonical x25519.Key
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		x25519.KeyGen(&canonical, &secret)

		highBit := canonical
		highBit[x25519.Size-1] |= 0x80

		var ssCanonical, ssHighBit x25519.Key
		if !x25519.Shared(&ssCanonical, &secret, &canonical) {
			t.Fatal("generated canonical key was rejected")
		}
		if !x25519.Shared(&ssHighBit, &secret, &highBit) {
			t.Fatal("high-bit representation changed acceptance")
		}
		if ssCanonical != ssHighBit {
			t.Fatal("high-bit representation changed the shared secret")
		}
	}
}

func TestX25519HPKEValidRepresentationsRemainAccepted(t *testing.T) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	suite := hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_ChaCha20Poly1305,
	)
	seed := bytes.Repeat([]byte{'V'}, scheme.EncapsulationSeedSize())

	for _, encoding := range equivalentX25519Encodings(t, rfc7748BobPublic) {
		t.Run(encoding.name, func(t *testing.T) {
			pk, err := scheme.UnmarshalBinaryPublicKey(encoding.bytes)
			if err != nil {
				t.Fatalf("UnmarshalBinaryPublicKey: %v", err)
			}

			ct, ss, err := scheme.EncapsulateDeterministically(pk, seed)
			if err != nil {
				t.Fatalf("EncapsulateDeterministically rejected valid point: %v", err)
			}
			if len(ct) != scheme.CiphertextSize() || len(ss) != scheme.SharedKeySize() {
				t.Fatal("valid encapsulation returned incorrectly sized outputs")
			}

			sender, err := suite.NewSender(pk, nil)
			if err != nil {
				t.Fatal(err)
			}
			enc, sealer, err := sender.Setup(bytes.NewReader(seed))
			if err != nil {
				t.Fatalf("Sender.Setup rejected valid point representation: %v", err)
			}
			if len(enc) != scheme.CiphertextSize() || sealer == nil {
				t.Fatal("valid setup did not return a usable context")
			}
		})
	}
}

func TestX25519MalformedPeerKeysDoNotProduceKeysOrContexts(t *testing.T) {
	secret := decodeHexKey(t, rfc7748AlicePrivate)
	env := newHPKEBoundary(t)

	for _, length := range []int{0, x25519.Size - 1, x25519.Size + 1} {
		peer := bytes.Repeat([]byte{0x01}, length)

		key, err := deriveCheckedX25519Key(&secret, peer)
		if err == nil {
			t.Fatalf("direct derivation accepted %d-byte peer key", length)
		}
		if key != nil {
			t.Fatalf("%d-byte peer key produced a consumable key", length)
		}

		pk, err := env.scheme.UnmarshalBinaryPublicKey(peer)
		if err == nil {
			t.Fatalf("HPKE unmarshal accepted %d-byte peer key", length)
		}
		if pk != nil {
			t.Fatalf("%d-byte peer key produced a public key object", length)
		}

		receiver, err := env.suite.NewReceiver(env.skR, nil)
		if err != nil {
			t.Fatal(err)
		}
		opener, err := receiver.Setup(peer)
		if err == nil {
			t.Fatalf("HPKE Receiver.Setup accepted %d-byte encapsulated key", length)
		}
		if opener != nil {
			t.Fatalf("%d-byte encapsulated key produced an opener", length)
		}
	}
}

func TestX25519HPKEValidSessionRemainsSuccessful(t *testing.T) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	suite := hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_ChaCha20Poly1305,
	)

	bobPrivBytes := hexBytes(t, rfc7748BobPrivate)
	bobPubBytes := hexBytes(t, rfc7748BobPublic)
	alicePrivBytes := hexBytes(t, rfc7748AlicePrivate)
	alicePubBytes := hexBytes(t, rfc7748AlicePublic)

	skR, err := scheme.UnmarshalBinaryPrivateKey(bobPrivBytes)
	if err != nil {
		t.Fatal(err)
	}
	pkR, err := scheme.UnmarshalBinaryPublicKey(bobPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	skS, err := scheme.UnmarshalBinaryPrivateKey(alicePrivBytes)
	if err != nil {
		t.Fatal(err)
	}
	pkS, err := scheme.UnmarshalBinaryPublicKey(alicePubBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !skS.Public().Equal(pkS) {
		t.Fatal("Alice public key does not match her private key")
	}

	seed := bytes.Repeat([]byte{'K'}, scheme.EncapsulationSeedSize())
	ct, wantSS, err := scheme.EncapsulateDeterministically(pkR, seed)
	if err != nil {
		t.Fatal(err)
	}
	gotSS, err := scheme.Decapsulate(skR, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSS, wantSS) {
		t.Fatal("deterministic KEM shared secrets do not match")
	}

	info := []byte("integration session")
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("Sender.Setup: %v", err)
	}

	plaintext := []byte("valid X25519 HPKE session")
	aad := []byte("associated data")
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatalf("Receiver.Setup: %v", err)
	}
	gotPT, err := opener.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(gotPT, plaintext) {
		t.Fatal("HPKE plaintext mismatch")
	}

	authSender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatal(err)
	}
	authEnc, authSealer, err := authSender.SetupAuth(bytes.NewReader(seed), skS)
	if err != nil {
		t.Fatalf("Sender.SetupAuth: %v", err)
	}
	authCT, err := authSealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	authReceiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		t.Fatal(err)
	}
	authOpener, err := authReceiver.SetupAuth(authEnc, pkS)
	if err != nil {
		t.Fatalf("Receiver.SetupAuth: %v", err)
	}
	gotPT, err = authOpener.Open(authCT, aad)
	if err != nil {
		t.Fatalf("auth Open: %v", err)
	}
	if !bytes.Equal(gotPT, plaintext) {
		t.Fatal("authenticated HPKE plaintext mismatch")
	}
}
