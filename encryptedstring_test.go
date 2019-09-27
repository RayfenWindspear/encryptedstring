package encryptedstring

import (
	"testing"
)

const notEqual = "before/after values not equal"

func init() {
	err := AddKey("encrypt", []byte("Y53DIiG6XX7eguA0SOzK7p6EPV7wfRNe"))
	if err != nil {
		panic(err)
	}
}

func TestEncryptDecryptString(t *testing.T) {
	const s = `Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.
				Hello World, how are you? I'm choosing a rather long string now.`
	var e EncryptedString = EncryptedString(s)
	enc, err := e.Encrypt()
	if err != nil {
		t.Error(err)
	}

	plain, err := e.Decrypt(enc)
	if err != nil {
		t.Error(err)
	}

	if string(plain) != s {
		t.Error(notEqual)
	}
}

func TestValuerScanner(t *testing.T) {
	const thevalue = "Hello World"
	var v = EncryptedString(thevalue)
	val, err := v.Value()
	if err != nil {
		t.Error(err)
	}
	value, ok := val.([]byte)
	if !ok {
		t.Error("not a []byte")
	}

	var s EncryptedString
	var p = &s
	p.Scan(value)

	if thevalue != s {
		t.Error(notEqual)
	}
}

func TestEncryptDecryptEmptyString(t *testing.T) {
	const s = ""
	var e EncryptedString = EncryptedString(s)
	enc, err := e.Encrypt()
	if err != nil {
		t.Error(err)
	}

	plain, err := e.Decrypt(enc)
	if err != nil {
		t.Error(err)
	}

	if string(plain) != s {
		t.Error(notEqual)
	}
}

func TestValuerScannerEmptyString(t *testing.T) {
	const thevalue = ""
	var v = EncryptedString(thevalue)
	val, err := v.Value()
	if err != nil {
		t.Error(err)
	}
	value, ok := val.([]byte)
	if !ok {
		t.Error("not a []byte")
	}

	var s EncryptedString
	p := &s
	p.Scan(value)

	if thevalue != s {
		t.Error(notEqual)
	}
}
