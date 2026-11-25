// Package ed25519 implements Ed25519 signature scheme as described in RFC-8032.
//
// This package provides optimized implementations of the three signature
// variants and maintaining almost full compatibility with crypto/ed25519.
//
//	| Scheme Name | Sign Function     | Verification  | Context           |
//	|-------------|-------------------|---------------|-------------------|
//	| Ed25519     | Sign              | Verify        | None              |
//	| Ed25519Ph   | SignPh            | VerifyPh      | Yes, can be empty |
//	| Ed25519Ctx  | SignWithCtx       | VerifyWithCtx | Yes, non-empty    |
//	| All above   | (PrivateKey).Sign | VerifyAny     | As above          |
//
// Specific functions for sign and verify are defined. A generic signing
// function for all schemes is available through the crypto.Signer interface,
// which is implemented by the PrivateKey type. A correspond all-in-one
// verification method is provided by the VerifyAny function.
//
// Signing with Ed25519Ph or Ed25519Ctx requires a context string for domain
// separation. This parameter is passed using a SignerOptions struct defined
// in this package. While Ed25519Ph accepts an empty context, Ed25519Ctx
// enforces non-empty context strings.
//
// # Compatibility with crypto.ed25519
//
// These functions are compatible with the “Ed25519” function defined in
// RFC-8032. However, unlike RFC 8032's formulation, this package's private
// key representation includes a public key suffix to make multiple signing
// operations with the same key more efficient. This package refers to the
// RFC-8032 private key as the “seed”.
//
// Public keys are decoded following RFC 8032 strictly: an encoding whose
// y-coordinate is not reduced modulo 2^255-19, or whose x-coordinate is zero
// with the sign bit set, is rejected. crypto/ed25519 accepts those
// non-canonical encodings instead, so for a small, fixed set of malformed
// public keys the verification functions here return false where
// crypto/ed25519 returns true.
//
// References
//
//   - RFC-8032: https://rfc-editor.org/rfc/rfc8032.txt
//   - Ed25519: https://ed25519.cr.yp.to/
//   - EdDSA: High-speed high-security signatures. https://doi.org/10.1007/s13389-012-0027-1
package ed25519

import (
	"bytes"
	"crypto"
	cryptoEd25519 "crypto/ed25519"
	cryptoRand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/cloudflare/circl/sign"
)

const (
	// ContextMaxSize is the maximum length (in bytes) allowed for context.
	ContextMaxSize = 255
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

const (
	paramB = 256 / 8 // Size of keys in bytes.
)

// SignerOptions implements crypto.SignerOpts and augments with parameters
// that are specific to the Ed25519 signature schemes.
type SignerOptions struct {
	// Hash must be crypto.Hash(0) for Ed25519/Ed25519ctx, or crypto.SHA512
	// for Ed25519ph.
	crypto.Hash

	// Context is an optional domain separation string for Ed25519ph and a
	// must for Ed25519ctx. Its length must be less or equal than 255 bytes.
	Context string

	// Scheme is an identifier for choosing a signature scheme. The zero value
	// is ED25519.
	Scheme SchemeID
}

// SchemeID is an identifier for each signature scheme.
type SchemeID uint

const (
	ED25519 SchemeID = iota
	ED25519Ph
	ED25519Ctx
)

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	return ok && subtle.ConstantTimeCompare(priv, xx) == 1
}

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make(PublicKey, PublicKeySize)
	copy(publicKey, priv[SeedSize:])
	return publicKey
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:SeedSize])
	return seed
}

func (priv PrivateKey) Scheme() sign.Scheme { return sch }

func (pub PublicKey) Scheme() sign.Scheme { return sch }

func (priv PrivateKey) MarshalBinary() (data []byte, err error) {
	privateKey := make(PrivateKey, PrivateKeySize)
	copy(privateKey, priv)
	return privateKey, nil
}

func (pub PublicKey) MarshalBinary() (data []byte, err error) {
	publicKey := make(PublicKey, PublicKeySize)
	copy(publicKey, pub)
	return publicKey, nil
}

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	return ok && bytes.Equal(pub, xx)
}

// Sign creates a signature of a message with priv key.
// This function is compatible with crypto.ed25519 and also supports the
// three signature variants defined in RFC-8032, namely Ed25519 (or pure
// EdDSA), Ed25519Ph, and Ed25519Ctx.
// The opts.HashFunc() must return zero to specify either Ed25519 or Ed25519Ctx
// variant. This can be achieved by passing crypto.Hash(0) as the value for
// opts.
// The opts.HashFunc() must return SHA512 to specify the Ed25519Ph variant.
// This can be achieved by passing crypto.SHA512 as the value for opts.
// Use a SignerOptions struct (defined in this package) to pass a context
// string for signing. SignerOptions may be passed by value or by pointer;
// nil selects plain Ed25519. Message and context semantics are the same as
// for Sign, SignPh, and SignWithCtx.
func (priv PrivateKey) Sign(
	rand io.Reader,
	message []byte,
	opts crypto.SignerOpts,
) (signature []byte, err error) {
	cfg, err := signerConfigFromOpts(opts)
	if err != nil {
		return nil, err
	}

	switch cfg.scheme {
	case ED25519:
		return Sign(priv, message), nil
	case ED25519Ph:
		return SignPh(priv, message, cfg.context), nil
	case ED25519Ctx:
		return SignWithCtx(priv, message, cfg.context), nil
	default:
		return nil, errBadHashAlgorithm
	}
}

// SignMessage has the same message semantics as Sign in this package: the
// message passed for Ed25519ph is hashed internally. It implements
// crypto.MessageSigner for callers that select the raw-message interface.
func (priv PrivateKey) SignMessage(
	rand io.Reader,
	message []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	return priv.Sign(rand, message, opts)
}

var errBadHashAlgorithm = errors.New("ed25519: bad hash algorithm")

// signerConfig is the resolved RFC 8032 variant and domain-separation
// context used by the generic crypto.Signer and verification entry points.
type signerConfig struct {
	scheme  SchemeID
	context string
}

// signerConfigFromOpts maps every supported options representation to the
// same variant and context used by the direct Sign, SignPh, and SignWithCtx
// functions. In particular, both values and pointers are recognized.
func signerConfigFromOpts(opts crypto.SignerOpts) (signerConfig, error) {
	cfg := signerConfig{scheme: ED25519}
	var hash crypto.Hash
	explicitScheme := false

	switch o := opts.(type) {
	case nil:
		return cfg, nil
	case SignerOptions:
		cfg.scheme = o.Scheme
		cfg.context = o.Context
		hash = o.Hash
		explicitScheme = true
	case *SignerOptions:
		if o == nil {
			return cfg, nil
		}
		cfg.scheme = o.Scheme
		cfg.context = o.Context
		hash = o.Hash
		explicitScheme = true
	case sign.SignatureOpts:
		cfg.context = o.Context
		hash = o.Hash
	case *sign.SignatureOpts:
		if o == nil {
			return cfg, nil
		}
		cfg.context = o.Context
		hash = o.Hash
	case sign.TestingSignerOpts:
		cfg.context = o.Context
		hash = o.Hash
	case *sign.TestingSignerOpts:
		if o == nil {
			return cfg, nil
		}
		cfg.context = o.Context
		hash = o.Hash
	case *cryptoEd25519.Options:
		if o == nil {
			return cfg, nil
		}
		cfg.context = o.Context
		hash = o.Hash
	default:
		hash = opts.HashFunc()
	}

	if len(cfg.context) > ContextMaxSize {
		return signerConfig{}, fmt.Errorf("ed25519: bad context length: %v > %v",
			len(cfg.context), ContextMaxSize)
	}

	// The zero SchemeID is ED25519, so options that do not expose a Scheme
	// select the variant from the hash and context as in crypto/ed25519.
	// Apply the same inference to a zero-valued SignerOptions so that its
	// Context field is never silently ignored.
	if !explicitScheme || cfg.scheme == ED25519 {
		switch {
		case hash == crypto.SHA512:
			cfg.scheme = ED25519Ph
		case hash == crypto.Hash(0) && cfg.context != "":
			cfg.scheme = ED25519Ctx
		case hash == crypto.Hash(0):
			cfg.scheme = ED25519
		default:
			return signerConfig{}, errBadHashAlgorithm
		}
	}

	switch cfg.scheme {
	case ED25519:
		if hash != crypto.Hash(0) || cfg.context != "" {
			return signerConfig{}, errBadHashAlgorithm
		}
	case ED25519Ph:
		if hash != crypto.SHA512 {
			return signerConfig{}, errBadHashAlgorithm
		}
	case ED25519Ctx:
		if hash != crypto.Hash(0) || cfg.context == "" {
			return signerConfig{}, errBadHashAlgorithm
		}
	default:
		return signerConfig{}, errBadHashAlgorithm
	}

	return cfg, nil
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptoRand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make(PublicKey, PublicKeySize)
	copy(publicKey, privateKey[SeedSize:])

	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	privateKey := make(PrivateKey, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}
	var P pointR1
	k := sha512.Sum512(seed)
	clamp(k[:])
	reduceModOrder(k[:paramB], false)
	P.fixedMult(k[:paramB])
	copy(privateKey[:SeedSize], seed)
	_ = P.ToBytes(privateKey[SeedSize:])
}

func signAll(signature []byte, privateKey PrivateKey, message, ctx []byte, preHash bool) {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	H := sha512.New()
	var PHM []byte

	if preHash {
		_, _ = H.Write(message)
		PHM = H.Sum(nil)
		H.Reset()
	} else {
		PHM = message
	}

	// 1.  Hash the 32-byte private key using SHA-512.
	_, _ = H.Write(privateKey[:SeedSize])
	h := H.Sum(nil)
	clamp(h[:])
	prefix, s := h[paramB:], h[:paramB]

	// 2.  Compute SHA-512(dom2(F, C) || prefix || PH(M))
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(prefix)
	_, _ = H.Write(PHM)
	r := H.Sum(nil)
	reduceModOrder(r[:], true)

	// 3.  Compute the point [r]B.
	var P pointR1
	P.fixedMult(r[:paramB])
	R := (&[paramB]byte{})[:]
	if err := P.ToBytes(R); err != nil {
		panic(err)
	}

	// 4.  Compute SHA512(dom2(F, C) || R || A || PH(M)).
	H.Reset()

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(privateKey[SeedSize:])
	_, _ = H.Write(PHM)
	hRAM := H.Sum(nil)

	reduceModOrder(hRAM[:], true)

	// 5.  Compute S = (r + k * s) mod order.
	S := (&[paramB]byte{})[:]
	calculateS(S, r[:paramB], hRAM[:paramB], s)

	// 6.  The signature is the concatenation of R and S.
	copy(signature[:paramB], R[:])
	copy(signature[paramB:], S[:])
}

// Sign signs the message with privateKey and returns a signature.
// This function supports the signature variant defined in RFC-8032: Ed25519,
// also known as the pure version of EdDSA.
// It will panic if len(privateKey) is not PrivateKeySize.
func Sign(privateKey PrivateKey, message []byte) []byte {
	signature := make([]byte, SignatureSize)
	signAll(signature, privateKey, message, []byte(""), false)
	return signature
}

// SignPh creates a signature of a message with private key and context.
// This function supports the signature variant defined in RFC-8032: Ed25519ph,
// meaning it internally hashes the message using SHA-512, and optionally
// accepts a context string.
// It will panic if len(privateKey) is not PrivateKeySize.
// Context could be passed to this function, which length should be no more than
// ContextMaxSize=255. It can be empty.
func SignPh(privateKey PrivateKey, message []byte, ctx string) []byte {
	if len(ctx) > ContextMaxSize {
		panic(fmt.Errorf("ed25519: bad context length: %v", len(ctx)))
	}

	signature := make([]byte, SignatureSize)
	signAll(signature, privateKey, message, []byte(ctx), true)
	return signature
}

// SignWithCtx creates a signature of a message with private key and context.
// This function supports the signature variant defined in RFC-8032: Ed25519ctx,
// meaning it accepts a non-empty context string.
// It will panic if len(privateKey) is not PrivateKeySize.
// Context must be passed to this function, which length should be no more than
// ContextMaxSize=255 and cannot be empty.
func SignWithCtx(privateKey PrivateKey, message []byte, ctx string) []byte {
	if len(ctx) == 0 || len(ctx) > ContextMaxSize {
		panic(fmt.Errorf("ed25519: bad context length: %v > %v", len(ctx), ContextMaxSize))
	}

	signature := make([]byte, SignatureSize)
	signAll(signature, privateKey, message, []byte(ctx), false)
	return signature
}

func verify(public PublicKey, message, signature, ctx []byte, preHash bool) bool {
	if len(public) != PublicKeySize ||
		len(signature) != SignatureSize ||
		len(ctx) > ContextMaxSize ||
		!isLessThanOrder(signature[paramB:]) {
		return false
	}

	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}

	H := sha512.New()
	var PHM []byte

	if preHash {
		_, _ = H.Write(message)
		PHM = H.Sum(nil)
		H.Reset()
	} else {
		PHM = message
	}

	R := signature[:paramB]

	writeDom(H, ctx, preHash)

	_, _ = H.Write(R)
	_, _ = H.Write(public)
	_, _ = H.Write(PHM)
	hRAM := H.Sum(nil)
	reduceModOrder(hRAM[:], true)

	var Q pointR1
	encR := (&[paramB]byte{})[:]
	P.neg()
	Q.doubleMult(&P, signature[paramB:], hRAM[:paramB])
	_ = Q.ToBytes(encR)
	return bytes.Equal(R, encR)
}

// VerifyAny returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports all the three signature variants defined in RFC-8032,
// namely Ed25519 (or pure EdDSA), Ed25519Ph, and Ed25519Ctx.
// The opts.HashFunc() must return zero to specify either Ed25519 or Ed25519Ctx
// variant. This can be achieved by passing crypto.Hash(0) as the value for opts.
// The opts.HashFunc() must return SHA512 to specify the Ed25519Ph variant.
// This can be achieved by passing crypto.SHA512 as the value for opts.
// Use a SignerOptions struct to pass a context string for signing.
func VerifyAny(public PublicKey, message, signature []byte, opts crypto.SignerOpts) bool {
	cfg, err := signerConfigFromOpts(opts)
	if err != nil {
		return false
	}

	switch cfg.scheme {
	case ED25519:
		return Verify(public, message, signature)
	case ED25519Ph:
		return VerifyPh(public, message, signature, cfg.context)
	case ED25519Ctx:
		return VerifyWithCtx(public, message, signature, cfg.context)
	default:
		return false
	}
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports the signature variant defined in RFC-8032: Ed25519,
// also known as the pure version of EdDSA.
func Verify(public PublicKey, message, signature []byte) bool {
	return verify(public, message, signature, []byte(""), false)
}

// VerifyPh returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
// This function supports the signature variant defined in RFC-8032: Ed25519ph,
// meaning it internally hashes the message using SHA-512.
// Context could be passed to this function, which length should be no more than
// 255. It can be empty.
func VerifyPh(public PublicKey, message, signature []byte, ctx string) bool {
	return verify(public, message, signature, []byte(ctx), true)
}

// VerifyWithCtx returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded, or when context is
// not provided.
// This function supports the signature variant defined in RFC-8032: Ed25519ctx,
// meaning it does not handle prehashed messages. Non-empty context string must be
// provided, and must not be more than 255 of length.
func VerifyWithCtx(public PublicKey, message, signature []byte, ctx string) bool {
	if len(ctx) == 0 || len(ctx) > ContextMaxSize {
		return false
	}

	return verify(public, message, signature, []byte(ctx), false)
}

func clamp(k []byte) {
	k[0] &= 248
	k[paramB-1] = (k[paramB-1] & 127) | 64
}

// isLessThanOrder returns true if 0 <= x < order.
func isLessThanOrder(x []byte) bool {
	i := len(order) - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[i] < order[i]
}

func writeDom(h io.Writer, ctx []byte, preHash bool) {
	dom2 := "SigEd25519 no Ed25519 collisions"

	if len(ctx) > 0 {
		_, _ = h.Write([]byte(dom2))
		if preHash {
			_, _ = h.Write([]byte{byte(0x01), byte(len(ctx))})
		} else {
			_, _ = h.Write([]byte{byte(0x00), byte(len(ctx))})
		}
		_, _ = h.Write(ctx)
	} else if preHash {
		_, _ = h.Write([]byte(dom2))
		_, _ = h.Write([]byte{0x01, 0x00})
	}
}
