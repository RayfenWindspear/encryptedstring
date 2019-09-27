package encryptedstring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	encryptionKeys = make(map[string][]byte)

	ErrShortCipher      = errors.New("ciphertext too short.")
	ErrVersionMismatch  = errors.New("version mismatch.")
	ErrSrcNotBytes      = errors.New("EncryptedString Scan src not a []byte.")
	ErrNoSuchKey        = errors.New("No such key exists.")
	ErrKeyAlreadyExists = errors.New("Key with this name already exists.")
)

const (
	encryptionVersion byte = 0x00
	blockSize              = 12
)

func AddKey(name string, key []byte) error {
	if _, exists := encryptionKeys[name]; exists {
		return ErrKeyAlreadyExists
	}
	encryptionKeys[name] = key
	return nil
}

// EncryptedString type is a string that will encrypt and decrypt on the fly when used with a database/sql/driver.
// It can also be encoding/json Marshaled and Unmarshaled with the same effect.
type EncryptedString string

// Value calls encrypt on the string before storing it
func (e EncryptedString) Value() (driver.Value, error) {
	if e == "" {
		// don't bother encrypting nothing
		return []byte{}, nil
	}
	val, err := e.Encrypt()
	if err != nil {
		return []byte{}, err
	}
	return val, nil
}

// Scan calls decrypt on the string before
func (e *EncryptedString) Scan(src interface{}) error {
	v, ok := src.([]byte)
	if !ok {
		return ErrSrcNotBytes
	}
	if len(v) == 0 {
		// emptystring
		*e = ""
		return nil
	}
	val, err := e.Decrypt(v)
	if err != nil {
		return err
	}
	*e = EncryptedString(val)
	return nil
}

func (e EncryptedString) MarshalJSON() ([]byte, error) {
	enc, err := e.Encrypt()
	if err != nil {
		return nil, err
	}
	return json.Marshal(base64.URLEncoding.EncodeToString(enc))
}

func (e *EncryptedString) UnmarshalJSON(b64 []byte) error {
	// strip the quotes
	b64 = b64[1 : len(b64)-1]
	ciphertext := make([]byte, base64.URLEncoding.DecodedLen(len(b64)))
	l, err := base64.URLEncoding.Decode(ciphertext, b64)
	if err != nil {
		return err
	}
	v, err := e.Decrypt(ciphertext[:l])
	*e = EncryptedString(v)
	return err
}

// Encrypt encrypts the string using AES with GCM
func (e EncryptedString) Encrypt() ([]byte, error) {
	block, err := aes.NewCipher(encryptionKeys["encrypt"])
	if err != nil {
		return nil, err
	}
	var ciphertext []byte

	// add the version byte to the front
	ciphertext = append(ciphertext, encryptionVersion)

	nonce := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext = append(ciphertext, nonce...)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cText := aesgcm.Seal(nil, nonce, []byte(e), nil)

	ciphertext = append(ciphertext, cText...)
	return ciphertext, nil
}

// Decrypt is used by the Scanner to decrypt the value incoming from the DB
func (e EncryptedString) Decrypt(ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(encryptionKeys["encrypt"])
	if err != nil {
		return "", err
	}

	version := ciphertext[0]
	if version != encryptionVersion {
		fmt.Println("Encryption versions don't match")
		// TODO if/when the version is updated, handle whatever needs to be done here.
		return "", ErrVersionMismatch
	}

	// The nonce needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < blockSize+1 {
		return "", ErrShortCipher
	}
	nonce := ciphertext[1 : blockSize+1]

	// Get a GCM instance that uses the AES cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext = ciphertext[blockSize+1:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// BlindIndexHash just does a sha512 HMAC hash. Good enough for queryable values that don't need to be crazy secure (most values), however
// these are NOT reversable. They are usually accompanied by an encrypted version though, so this is just to allow 1:1 queries.
// Note that the Valuer interface will hash the string autmatically if it is used as a bound parameter.
type BlindIndexHash string

func (b BlindIndexHash) Value() (driver.Value, error) {
	if b == "" {
		// don't bother encrypting nothing
		return "", nil
	}
	val, err := b.GetBase64()
	if err != nil {
		return "", err
	}
	return val, nil
}

func (b BlindIndexHash) GetHash() ([]byte, error) {
	mac := hmac.New(sha512.New, encryptionKeys["blindIndex"])
	_, err := mac.Write([]byte(b))
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// GetBase64 returns the Base64 string value of the hashed value. Used for programmatically comparing values.
func (b BlindIndexHash) GetBase64() (string, error) {
	byts, err := b.GetHash()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(byts), nil
}

// BlindIndexStrong should only be used for extremely sensitive pieces of data that need to be 1:1 queried, such as an SSN.
// We usually don't store these types of values, so please use BlindIndexHash instead.
type BlindIndexStrong string

// TODO implement
func (b BlindIndexStrong) getStrongHash() ([]byte, error) {
	return nil, nil
}
