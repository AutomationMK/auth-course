package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
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
	http.HandleFunc("/", hmacExp)
	http.HandleFunc("/submit", hmacSubmit)
	http.ListenAndServe(":8080", nil)
}

func hmacExp(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	isEqual := true
	xs := strings.SplitN(c.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code := hmacGetCode(cEmail)

		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}

	message := "Not logged in"
	if isEqual {
		message = "Logged in"
	}

	html := `<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>HMAC Example</title>
		</head>
		<body>
			<p>Cookie value:` + c.Value + `</p>
            <p>` + message + `</p>
			<form action="/submit" method="POST">
				<input type="email" name="email">
				<input type="submit">
			</form>
		</body>
	</html>`
	io.WriteString(w, html)
}

func hmacSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Printf("Error in parsing form: %s", err)
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	code := hmacGetCode(email)

	c := http.Cookie{
		Name:  "session",
		Value: code + "|" + email,
	}

	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func hmacGetCode(msg string) string {
	h := hmac.New(sha256.New, []byte("I love thursdays when it rains 1234"))
	h.Write([]byte(msg))
	return fmt.Sprintf("%x", h.Sum(nil))
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

func aesEncode(key []byte, input string) ([]byte, []byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in aesEncode while using NewCipher: %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)

	s := cipher.NewCTR(b, iv)

	buff := &bytes.Buffer{}
	sw := cipher.StreamWriter{
		S: s,
		W: buff,
	}
	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, nil, fmt.Errorf("Error in aesEncode while using StreamWriter.Write: %w", err)
	}

	return buff.Bytes(), iv, nil
}

func aesDecode(key, iv []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in aesDecode while using NewCipher: %w", err)
	}

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

func aesEncodeWriter(wtr io.Writer, key []byte) (io.Writer, []byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in aesEncodeWriter while using NewCipher: %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in aesEncodeWriter while using io.ReadFull for init vector: %w", err)
	}

	s := cipher.NewCTR(b, iv)

	return cipher.StreamWriter{
		S: s,
		W: wtr,
	}, iv, nil
}

func aesDecodeWriter(wtr io.Writer, key, iv []byte) (io.Writer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in aesDecodeWriter while using NewCipher: %w", err)
	}

	s := cipher.NewCTR(b, iv)

	return cipher.StreamWriter{
		S: s,
		W: wtr,
	}, nil
}
