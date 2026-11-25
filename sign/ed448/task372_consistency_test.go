package ed448_test

import (
	"bytes"
	"crypto"
	"testing"

	circsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/ed448"
)

func TestTask372GenericSignerOptionsConsistency(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("protocol message")
	ctx := "domain separation context"

	direct := map[string][]byte{
		"pure":       ed448.Sign(priv, msg, ""),
		"ctx":        ed448.Sign(priv, msg, ctx),
		"ph":         ed448.SignPh(priv, msg, ""),
		"ph-context": ed448.SignPh(priv, msg, ctx),
	}

	tests := []struct {
		name string
		opts crypto.SignerOpts
		want []byte
	}{
		{"nil", nil, direct["pure"]},
		{"hash zero", crypto.Hash(0), direct["pure"]},
		{"value pure", ed448.SignerOptions{Scheme: ed448.ED448}, direct["pure"]},
		{"pointer pure", &ed448.SignerOptions{Scheme: ed448.ED448}, direct["pure"]},
		{
			"value context",
			ed448.SignerOptions{Scheme: ed448.ED448, Context: ctx},
			direct["ctx"],
		},
		{
			"pointer context",
			&ed448.SignerOptions{Scheme: ed448.ED448, Context: ctx},
			direct["ctx"],
		},
		{
			"value ph",
			ed448.SignerOptions{Scheme: ed448.ED448Ph},
			direct["ph"],
		},
		{
			"pointer ph",
			&ed448.SignerOptions{Scheme: ed448.ED448Ph},
			direct["ph"],
		},
		{
			"value ph context",
			ed448.SignerOptions{Scheme: ed448.ED448Ph, Context: ctx},
			direct["ph-context"],
		},
		{
			"pointer ph context",
			&ed448.SignerOptions{Scheme: ed448.ED448Ph, Context: ctx},
			direct["ph-context"],
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
			if !ed448.VerifyAny(pub, msg, sig, tc.opts) {
				t.Fatal("VerifyAny rejected a signature made with the same options")
			}
		})
	}
}

func TestTask372Ed448DomainSeparationEntries(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(nil)
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
			ed448.Sign(priv, msg, ""),
			ed448.SignerOptions{Scheme: ed448.ED448},
		},
		{
			"context",
			ed448.Sign(priv, msg, ctx),
			&ed448.SignerOptions{Scheme: ed448.ED448, Context: ctx},
		},
		{
			"ph empty",
			ed448.SignPh(priv, msg, ""),
			ed448.SignerOptions{Scheme: ed448.ED448Ph},
		},
		{
			"ph context",
			ed448.SignPh(priv, msg, ctx),
			&ed448.SignerOptions{Scheme: ed448.ED448Ph, Context: ctx},
		},
	}

	for i, signed := range variants {
		for j, verify := range variants {
			got := ed448.VerifyAny(pub, msg, signed.sig, verify.opts)
			want := i == j
			if got != want {
				t.Errorf("%s signature verified as %s: got %v, want %v",
					signed.name, verify.name, got, want)
			}
		}

		if ed448.VerifyAny(pub, msg, signed.sig, &ed448.SignerOptions{
			Scheme:  ed448.ED448,
			Context: otherCtx,
		}) {
			t.Errorf("%s signature accepted under another context", signed.name)
		}

		badSig := bytes.Clone(signed.sig)
		badSig[len(badSig)-1] ^= 1
		if ed448.VerifyAny(pub, msg, badSig, signed.opts) {
			t.Errorf("corrupted %s signature was accepted", signed.name)
		}
	}
}

func TestTask372GenericSchemeEntryConsistency(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("protocol message")
	ctx := "context"
	scheme := ed448.Scheme()

	opts := &circsign.SignatureOpts{Context: ctx}
	sig := scheme.Sign(priv, msg, opts)
	want := ed448.Sign(priv, msg, ctx)
	if !bytes.Equal(sig, want) {
		t.Fatal("scheme.Sign does not match direct Sign")
	}
	if !scheme.Verify(pub, msg, sig, opts) {
		t.Fatal("scheme.Verify rejected signature")
	}
	if scheme.Verify(pub, msg, sig, &circsign.SignatureOpts{Context: "other"}) {
		t.Fatal("scheme.Verify accepted signature under another context")
	}
}

func TestTask372Ed448GenericInvalidOptions(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("protocol message")
	bigCtx := string(make([]byte, ed448.ContextMaxSize+1))

	invalid := []crypto.SignerOpts{
		crypto.SHA224,
		&ed448.SignerOptions{Scheme: ed448.ED448, Hash: crypto.SHA512},
		&ed448.SignerOptions{Scheme: ed448.SchemeID(99)},
		&ed448.SignerOptions{Scheme: ed448.ED448, Context: bigCtx},
	}

	for _, opts := range invalid {
		sig, err := priv.Sign(nil, msg, opts)
		if err == nil {
			t.Errorf("Sign(%#v) succeeded", opts)
		}
		if sig != nil {
			t.Errorf("Sign(%#v) returned a partial signature", opts)
		}
		if ed448.VerifyAny(pub, msg, make([]byte, ed448.SignatureSize), opts) {
			t.Errorf("VerifyAny(%#v) accepted invalid options", opts)
		}
	}
}
