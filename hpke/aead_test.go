package hpke

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestAeadExporter(t *testing.T) {
	suite := Suite{kdfID: KDF_HKDF_SHA256, aeadID: AEAD_AES128GCM}
	exporter := &encdecContext{suite: suite}
	maxLength := uint(255 * suite.kdfID.ExtractSize())

	err := test.CheckPanic(func() {
		exporter.Export([]byte("exporter"), maxLength+1)
	})
	test.CheckNoErr(t, err, "exporter max size")
}

// setupAeadTest builds a matching sealer/opener pair with a fully initialized
// key schedule, so that the exporter is usable as well as the AEAD.
func setupAeadTest() (*sealContext, *openContext, error) {
	suite := NewSuite(KEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)
	pkR, skR, err := suite.kemID.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sender, err := suite.NewSender(pkR, nil)
	if err != nil {
		return nil, nil, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	receiver, err := suite.NewReceiver(skR, nil)
	if err != nil {
		return nil, nil, err
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, nil, err
	}

	return sealer.(*sealContext), opener.(*openContext), nil
}

func TestAeadNonceUpdate(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	numAttempts := 2
	var prevCt []byte
	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.Seal(pt, aad)
		if err != nil {
			t.Fatalf("encryption failed: %s", err)
		}

		if prevCt != nil && bytes.Equal(ct, prevCt) {
			t.Error("ciphertext matches the previous (nonce not updated)")
		}

		_, err = opener.Open(ct, aad)
		if err != nil {
			t.Errorf("decryption failed: %s", err)
		}

		prevCt = ct
	}
}

func TestOpenPhaseMismatch(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	recovered, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatalf("decryption failed: %s", err)
	}

	if !bytes.Equal(pt, recovered) {
		t.Fatal("Plaintext mismatch")
	}

	_, err = opener.Open(ct, aad)
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}
}

func TestSealPhaseMismatch(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	pt := []byte("plaintext")
	aad := []byte("aad")

	_, err = sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("encryption failed: %s", err)
	}

	_, err = opener.Open(ct, aad)
	if err == nil {
		t.Fatal("decryption succeeded when it should have failed")
	}
}

func TestAeadSeqOverflow(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	Nn := len(sealer.baseNonce)
	pt := []byte("plaintext")
	aad := []byte("aad")

	// Sets sequence number to 256 before its max value = 0xFF...FF.
	for i := 0; i < Nn; i++ {
		sealer.sequenceNumber[i] = 0xFF
		opener.sequenceNumber[i] = 0xFF
	}
	sealer.sequenceNumber[Nn-1] = 0x00
	opener.sequenceNumber[Nn-1] = 0x00

	numAttempts := 260
	wantCorrect := 2 * 255
	wantIncorrect := 2*numAttempts - wantCorrect
	gotCorrect := 0
	gotIncorrect := 0

	for i := 0; i < numAttempts; i++ {
		ct, err := sealer.Seal(pt, aad)
		switch {
		case ct != nil && err == nil:
			gotCorrect++
		case ct == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}

		pt2, err := opener.Open(ct, aad)
		switch {
		case pt2 != nil && err == nil:
			gotCorrect++
		case pt2 == nil && err != nil:
			gotIncorrect++
		default:
			t.FailNow()
		}
	}

	if gotCorrect != wantCorrect {
		test.ReportError(t, gotCorrect, wantCorrect)
	}
	if gotIncorrect != wantIncorrect {
		test.ReportError(t, gotIncorrect, wantIncorrect)
	}
}

// setSequenceNumber fills the context's big-endian sequence number with all
// 0xFF bytes except for its last byte, which is set to lastByte.
func setSequenceNumber(c *encdecContext, lastByte byte) {
	for i := range c.sequenceNumber {
		c.sequenceNumber[i] = 0xFF
	}
	c.sequenceNumber[len(c.sequenceNumber)-1] = lastByte
}

// TestAeadExhaustedContext checks the exhaustion boundary state transition
// required by Section 5.2 of RFC 9180: the last permitted seal/open succeeds at
// sequence number 0xFF...FE, after which both contexts transition to an
// exhausted state (sequence number 0xFF...FF) and never consume or produce
// message material again.
func TestAeadExhaustedContext(t *testing.T) {
	sealer, opener, err := setupAeadTest()
	test.CheckNoErr(t, err, "setup failed")

	Nn := len(sealer.baseNonce)
	pt := []byte("plaintext")
	aad := []byte("aad")
	exporterContext := []byte("exporter")

	// Exporter results do not depend on the sequence number; capture one before
	// exhaustion to prove they remain unchanged afterwards.
	wantExport := sealer.Export(exporterContext, uint(Nn))

	setSequenceNumber(sealer.encdecContext, 0xFE) // 0xFF...FE, the last usable sequence number.
	setSequenceNumber(opener.encdecContext, 0xFE)

	// The final message can still be sealed and opened.
	ct, err := sealer.Seal(pt, aad)
	if err != nil {
		t.Fatalf("seal of the last message failed: %s", err)
	}
	recovered, err := opener.Open(ct, aad)
	if err != nil {
		t.Fatalf("open of the last message failed: %s", err)
	}
	if !bytes.Equal(pt, recovered) {
		t.Fatal("plaintext mismatch for the last message")
	}

	// Both contexts are now exhausted and must keep the all-ones sequence.
	if !sealer.isExhausted() || !opener.isExhausted() {
		t.Fatal("contexts are not exhausted after the last message")
	}

	// Seal must fail without producing any ciphertext, and repeated calls must
	// keep failing without touching the exhausted state.
	for i := 0; i < 3; i++ {
		ct, err = sealer.Seal(pt, aad)
		if !errors.Is(err, ErrAEADSeqOverflows) {
			test.ReportError(t, err, ErrAEADSeqOverflows)
		}
		if ct != nil {
			t.Fatal("seal on an exhausted context produced ciphertext")
		}
		if !sealer.isExhausted() {
			t.Fatal("exhausted sealer left the exhausted state")
		}
	}

	// Open must fail without consuming any ciphertext, even when given a
	// ciphertext that is valid for the all-ones nonce, and repeated calls must
	// keep failing.
	validCt := sealer.cipherAtAllOnesNonce(t, pt, aad)
	for i := 0; i < 3; i++ {
		recovered, err = opener.Open(validCt, aad)
		if !errors.Is(err, ErrAEADSeqOverflows) {
			test.ReportError(t, err, ErrAEADSeqOverflows)
		}
		if recovered != nil {
			t.Fatal("open on an exhausted context produced plaintext")
		}
		if !opener.isExhausted() {
			t.Fatal("exhausted opener left the exhausted state")
		}
	}

	// The exhausted state survives serialization, which carries the sequence
	// number verbatim.
	raw, err := sealer.MarshalBinary()
	test.CheckNoErr(t, err, "marshal of exhausted sealer failed")
	restored, err := UnmarshalSealer(raw)
	test.CheckNoErr(t, err, "unmarshal of exhausted sealer failed")
	ct, err = restored.Seal(pt, aad)
	if !errors.Is(err, ErrAEADSeqOverflows) || ct != nil {
		t.Fatalf("restored sealer was not exhausted: ct=%v err=%v", ct, err)
	}

	raw, err = opener.MarshalBinary()
	test.CheckNoErr(t, err, "marshal of exhausted opener failed")
	restoredOpener, err := UnmarshalOpener(raw)
	test.CheckNoErr(t, err, "unmarshal of exhausted opener failed")
	recovered, err = restoredOpener.Open(validCt, aad)
	if !errors.Is(err, ErrAEADSeqOverflows) || recovered != nil {
		t.Fatalf("restored opener was not exhausted: pt=%v err=%v", recovered, err)
	}

	// Export remains available and unchanged after exhaustion.
	if gotExport := sealer.Export(exporterContext, uint(Nn)); !bytes.Equal(wantExport, gotExport) {
		t.Fatal("export result changed after exhaustion")
	}
	if gotExport := restored.Export(exporterContext, uint(Nn)); !bytes.Equal(wantExport, gotExport) {
		t.Fatal("export result changed across serialization")
	}
}

// cipherAtAllOnesNonce produces a ciphertext valid under the all-ones sequence
// number without going through the exhausted Sealer, so that Open can be shown
// to reject a genuinely valid ciphertext rather than failing authentication.
func (c *sealContext) cipherAtAllOnesNonce(t *testing.T, pt, aad []byte) []byte {
	t.Helper()
	saved := append([]byte(nil), c.sequenceNumber...)
	for i := range c.sequenceNumber {
		c.sequenceNumber[i] = 0xFF
	}
	ct := c.AEAD.Seal(nil, c.calcNonce(), pt, aad)
	copy(c.sequenceNumber, saved)
	return ct
}

// countingAEAD wraps an AEAD and records how often Seal/Open are invoked, so
// tests can assert that an exhausted context never consumes or generates
// message material.
type countingAEAD struct {
	cipher.AEAD
	sealCalls int
	openCalls int
}

func (c *countingAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	c.sealCalls++
	return c.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

func (c *countingAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	c.openCalls++
	return c.AEAD.Open(dst, nonce, ciphertext, additionalData)
}

// TestAeadExhaustedNoAeadCalls proves at the AEAD boundary that once the
// sequence number is exhausted, neither Seal nor Open ever reaches the
// underlying AEAD, even on repeated calls and even with a valid ciphertext.
func TestAeadExhaustedNoAeadCalls(t *testing.T) {
	suite := Suite{aeadID: AEAD_AES128GCM}
	key := make([]byte, suite.aeadID.KeySize())
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	base, err := suite.aeadID.New(key)
	if err != nil {
		t.Fatal(err)
	}
	Nn := suite.aeadID.NonceSize()
	baseNonce := make([]byte, Nn)

	sealAEAD, openAEAD := &countingAEAD{AEAD: base}, &countingAEAD{AEAD: base}
	sealer := &sealContext{&encdecContext{
		suite: suite, AEAD: sealAEAD, baseNonce: baseNonce,
		sequenceNumber: make([]byte, Nn), nonce: make([]byte, Nn),
	}}
	opener := &openContext{&encdecContext{
		suite: suite, AEAD: openAEAD, baseNonce: baseNonce,
		sequenceNumber: make([]byte, Nn), nonce: make([]byte, Nn),
	}}

	// Start both contexts directly in the exhausted 0xFF...FF state.
	for i := uint(0); i < Nn; i++ {
		sealer.sequenceNumber[i] = 0xFF
		opener.sequenceNumber[i] = 0xFF
	}

	pt, aad := []byte("plaintext"), []byte("aad")
	for i := 0; i < 3; i++ {
		if ct, err := sealer.Seal(pt, aad); !errors.Is(err, ErrAEADSeqOverflows) || ct != nil {
			t.Fatalf("exhausted Seal: ct=%v err=%v", ct, err)
		}
	}

	// A ciphertext genuinely valid under the all-ones nonce must be rejected
	// without being handed to the AEAD. It is produced with an independent AEAD
	// so that the counter on the context under test stays at zero.
	validCt := base.Seal(nil, sealer.calcNonce(), pt, aad)
	for i := 0; i < 3; i++ {
		if recovered, err := opener.Open(validCt, aad); !errors.Is(err, ErrAEADSeqOverflows) || recovered != nil {
			t.Fatalf("exhausted Open: pt=%v err=%v", recovered, err)
		}
	}

	if sealAEAD.sealCalls != 0 {
		test.ReportError(t, sealAEAD.sealCalls, 0)
	}
	if openAEAD.openCalls != 0 {
		test.ReportError(t, openAEAD.openCalls, 0)
	}
}
