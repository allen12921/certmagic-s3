package s3

import (
	"bytes"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	secret := []byte("12345678123456781234567812345678")
	var sbuf [32]byte

	copy(sbuf[:], secret)

	sb := SecretBoxIO{
		SecretKey: sbuf,
	}

	msg := []byte("This is a very important message that shall be encrypted...")
	r := sb.ByteReader(msg)

	buf, err := io.ReadAll(r)
	if err != nil {
		t.Errorf("encrypting failed: %v", err)
	}

	w := bytes.NewReader(buf)
	wb := sb.WrapReader(w)

	buf, err = io.ReadAll(wb)
	if err != nil {
		t.Errorf("decrypting failed: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("did not decrypt, got: %s", buf)
	}
}

func TestIOWrap(t *testing.T) {
	empty := bytes.NewReader(nil)

	sb := SecretBoxIO{}
	wr := sb.WrapReader(empty)

	buf, err := io.ReadAll(wr)
	if err != nil {
		t.Errorf("reading failed: %s", err)
	}
	if len(buf) != 0 {
		t.Errorf("Buffer should be empty, got: %v", buf)
	}
}

func TestCleartextIO(t *testing.T) {
	ci := &CleartextIO{}
	
	// Test ByteReader
	testData := []byte("test data")
	reader := ci.ByteReader(testData)
	
	result, err := io.ReadAll(&reader)
	if err != nil {
		t.Errorf("reading from ByteReader failed: %v", err)
	}
	
	if !bytes.Equal(result, testData) {
		t.Errorf("ByteReader data mismatch, got: %v, want: %v", result, testData)
	}
	
	// Test WrapReader
	input := bytes.NewReader(testData)
	wrapped := ci.WrapReader(input)
	
	result, err = io.ReadAll(wrapped)
	if err != nil {
		t.Errorf("reading from WrapReader failed: %v", err)
	}
	
	if !bytes.Equal(result, testData) {
		t.Errorf("WrapReader data mismatch, got: %v, want: %v", result, testData)
	}
}

func TestSecretBoxIOWithEmptyKey(t *testing.T) {
	sb := &SecretBoxIO{}
	
	// Test with empty data
	emptyData := []byte{}
	reader := sb.ByteReader(emptyData)
	
	result, err := io.ReadAll(&reader)
	if err != nil {
		t.Errorf("reading empty data failed: %v", err)
	}
	
	// Test decryption with empty key (should fail)
	wrapped := sb.WrapReader(bytes.NewReader(result))
	_, err = io.ReadAll(wrapped)
	
	// This should fail because the key is empty
	if err == nil {
		t.Errorf("decryption with empty key should fail but succeeded")
	}
}
