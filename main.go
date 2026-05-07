package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
	jwt.RegisteredClaims
	SessionID int64 `json:"session-id"`
}

func (u *UserClaims) Validate() error {
	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}
	return nil
}

func main() {
	msg := "This is totally fun get hands-on and learning it from the ground up."

	pass := "ilovedogs"
	bs, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		log.Panic("couldn't bcrypt password", err)
	}
	bs = bs[:16]

	rslt, err := encDecode(bs, msg)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("before base64", string(rslt))
	fmt.Println(base64.URLEncoding.EncodeToString(rslt))

	rslt2, err := encDecode(bs, string(rslt))
	if err != nil {
		log.Panic(err)
	}
	fmt.Println(string(rslt2))
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash pasword: %w", err)
	}
	return bs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, keys[currentKid].key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checksig while getting signature of message: %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing Token: %w", err)
	}
	return signedToken, nil
}

func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating key: %w", err)
	}
	uid, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating kid: %w", err)
	}

	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKid = uid.String()
	return nil
}

type key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]key{}

func parseToken(tokenStr string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}

		return k, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}

	return t.Claims.(*UserClaims), nil
}

func encDecode(key []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in encDecode while using NewCipher: %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)

	s := cipher.NewCTR(b, iv)

	buff := &bytes.Buffer{}
	sw := cipher.StreamWriter{
		S: s,
		W: buff,
	}
	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("Error in encDecode while using StreamWriter.Write: %w", err)
	}

	return buff.Bytes(), nil
}
