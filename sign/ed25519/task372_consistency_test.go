package ed25519_test

import (
	"bytes"
	"crypto"
	stded25519 "crypto/ed25519"
	"testing"

	circsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/ed25519"
)

func TestTask372GenericSignerOptionsConsistency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("protocol message")
	ctx := "domain separation context"

	direct := map[string][]byte{
		"pure":       ed25519.Sign(priv, msg),
		"ph":         ed25519.SignPh(priv, msg, ""),
		"ph-context": ed25519.SignPh(priv, msg, ctx),
		"ctx":        ed25519.SignWithCtx(priv, msg, ctx),
	}

	tests := []struct {
		name string
		opts crypto.SignerOpts
		want []byte
	}{
		{"nil", nil, direct["pure"]},
		{"hash zero", crypto.Hash(0), direct["pure"]},
		{"value pure", ed25519.SignerOptions{Scheme: ed25519.ED25519}, direct["pure"]},
		{"pointer pure", &ed25519.SignerOptions{Scheme: ed25519.ED25519}, direct["pure"]},
		{
			"value ph",
			ed25519.SignerOptions{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512},
			direct["ph"],
		},
		{
			"pointer ph",
			&ed25519.SignerOptions{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512},
			direct["ph"],
		},
		{
			"value ph context",
			ed25519.SignerOptions{
				Scheme:  ed25519.ED25519Ph,
				Hash:    crypto.SHA512,
				Context: ctx,
			},
			direct["ph-context"],
		},
		{
			"pointer ph context",
			&ed25519.SignerOptions{
				Scheme:  ed25519.ED25519Ph,
				Hash:    crypto.SHA512,
				Context: ctx,
			},
			direct["ph-context"],
		},
		{
			"value ctx",
			ed25519.SignerOptions{
				Scheme:  ed25519.ED25519Ctx,
				Context: ctx,
			},
			direct["ctx"],
		},
		{
			"pointer ctx",
			&ed25519.SignerOptions{
				Scheme:  ed25519.ED25519Ctx,
				Context: ctx,
			},
			direct["ctx"],
		},
		{
			"generic options context",
			circsign.SignatureOpts{Context: ctx},
			direct["ctx"],
		},
		{
			"generic pointer options context",
			&circsign.SignatureOpts{Context: ctx},
			direct["ctx"],
		},
		{
			"generic options ph context",
			circsign.SignatureOpts{Context: ctx, Hash: crypto.SHA512},
			direct["ph-context"],
		},
		{
			"generic pointer options ph context",
			&circsign.SignatureOpts{Context: ctx, Hash: crypto.SHA512},
			direct["ph-context"],
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := priv.Sign(nil, msg, tc.opts)
			if err != nil {
				t.Fatalf("Sign returned error: %v", err)
			}
			if !bytes.Equal(sig, tc.want) {
				t.Fatal("generic Sign does not match direct signing entry point")
			}
			if !ed25519.VerifyAny(pub, msg, sig, tc.opts) {
				t.Fatal("VerifyAny rejected a signature made with the same options")
			}
		})
	}
}

func TestTask372Ed25519DomainSeparationEntries(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("protocol message")
	ctx := "context"
	otherCtx := "other context"

	variants := []struct {
		name string
		sig  []byte
		opts crypto.SignerOpts
	}{
		{
			"pure",
			ed25519.Sign(priv, msg),
			ed25519.SignerOptions{Scheme: ed25519.ED25519},
		},
		{
			"ph empty",
			ed25519.SignPh(priv, msg, ""),
			ed25519.SignerOptions{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512},
		},
		{
			"ph context",
			ed25519.SignPh(priv, msg, ctx),
			&ed25519.SignerOptions{
				Scheme:  ed25519.ED25519Ph,
				Hash:    crypto.SHA512,
				Context: ctx,
			},
		},
		{
			"ctx",
			ed25519.SignWithCtx(priv, msg, ctx),
			&ed25519.SignerOptions{Scheme: ed25519.ED25519Ctx, Context: ctx},
		},
	}

	for i, signed := range variants {
		for j, verify := range variants {
			got := ed25519.VerifyAny(pub, msg, signed.sig, verify.opts)
			want := i == j
			if got != want {
				t.Errorf("%s signature verified as %s: got %v, want %v",
					signed.name, verify.name, got, want)
			}
		}

		if ed25519.VerifyAny(pub, msg, signed.sig, &ed25519.SignerOptions{
			Scheme:  ed25519.ED25519Ctx,
			Context: otherCtx,
		}) {
			t.Errorf("%s signature accepted under another context", signed.name)
		}

		badSig := bytes.Clone(signed.sig)
		badSig[len(badSig)-1] ^= 1
		if ed25519.VerifyAny(pub, msg, badSig, signed.opts) {
			t.Errorf("corrupted %s signature was accepted", signed.name)
		}
	}
}

func TestTask372GenericSchemeEntryConsistency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("protocol message")
	ctx := "context"
	scheme := ed25519.Scheme()

	if !scheme.SupportsContext() {
		t.Fatal("Ed25519 scheme should expose context support")
	}

	tests := []struct {
		name string
		opts *circsign.SignatureOpts
		want []byte
	}{
		{
			"pure",
			nil,
			ed25519.Sign(priv, msg),
		},
		{
			"context",
			&circsign.SignatureOpts{Context: ctx},
			ed25519.SignWithCtx(priv, msg, ctx),
		},
		{
			"prehash context",
			&circsign.SignatureOpts{Context: ctx, Hash: crypto.SHA512},
			ed25519.SignPh(priv, msg, ctx),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig := scheme.Sign(priv, msg, tc.opts)
			if !bytes.Equal(sig, tc.want) {
				t.Fatal("scheme.Sign does not match direct signing entry point")
			}
			if !scheme.Verify(pub, msg, sig, tc.opts) {
				t.Fatal("scheme.Verify rejected signature")
			}
		})
	}
}

func TestTask372StandardHashOptions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("protocol message")
	ctx := "context"

	tests := []struct {
		name string
		opts crypto.SignerOpts
		want []byte
	}{
		{
			"hash identifier",
			crypto.SHA512,
			ed25519.SignPh(priv, msg, ""),
		},
		{
			"standard options",
			&stded25519.Options{Hash: crypto.SHA512},
			ed25519.SignPh(priv, msg, ""),
		},
		{
			"standard options context",
			&stded25519.Options{Hash: crypto.SHA512, Context: ctx},
			ed25519.SignPh(priv, msg, ctx),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := priv.Sign(nil, msg, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, tc.want) {
				t.Fatal("generic Sign does not match direct SignPh")
			}
			if !ed25519.VerifyAny(pub, msg, sig, tc.opts) {
				t.Fatal("VerifyAny rejected signature")
			}

			messageSig, err := priv.SignMessage(nil, msg, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(messageSig, tc.want) {
				t.Fatal("SignMessage does not match direct SignPh")
			}
		})
	}
}

func TestTask372Ed25519GenericInvalidOptions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("protocol message")
	bigCtx := string(make([]byte, ed25519.ContextMaxSize+1))

	invalid := []crypto.SignerOpts{
		crypto.SHA224,
		&ed25519.SignerOptions{Scheme: ed25519.ED25519Ph, Hash: crypto.Hash(0)},
		&ed25519.SignerOptions{Scheme: ed25519.ED25519Ctx},
		&ed25519.SignerOptions{Scheme: ed25519.ED25519Ctx, Context: bigCtx},
		&ed25519.SignerOptions{Scheme: ed25519.ED25519Ph, Hash: crypto.SHA512, Context: bigCtx},
	}

	for _, opts := range invalid {
		sig, err := priv.Sign(nil, msg, opts)
		if err == nil {
			t.Errorf("Sign(%#v) succeeded", opts)
		}
		if sig != nil {
			t.Errorf("Sign(%#v) returned a partial signature", opts)
		}
		if ed25519.VerifyAny(pub, msg, make([]byte, ed25519.SignatureSize), opts) {
			t.Errorf("VerifyAny(%#v) accepted invalid options", opts)
		}
	}
}
