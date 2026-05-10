package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var db = make(map[string][]byte)
var key = "secretKey"

var ErrInvalidToken = errors.New("parseToken invalid token")

func main() {
	http.HandleFunc("/", register)
	http.HandleFunc("/register", postRegister)
	http.HandleFunc("/login", postLogin)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	regErrMsg := r.URL.Query().Get("regerrmsg")
	logErrMsg := r.URL.Query().Get("logerrmsg")
	html := fmt.Sprintf(`<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Ninja Level 2 Exercise 3</title>
			<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
		</head>
		<body class="flex flex-col items-center gap-20 mx-auto container px-4 pt-10 bg-slate-50">
			<form action="/register" method="POST"
				class="grid justify-items-center xl:grid-cols-2 bg-blue-300 w-full max-w-6xl gap-4 p-8 rounded-md shadow-md shadow-slate-500/20">
				<p class="lg:col-span-full text-red-500 font-bold">%s</p>
				<h2 class="text-xl md:text-2xl lg:text-4xl lg:col-span-full text-slate-50 font-bold text-center">
					Register Now
				</h2>
				<p class="text md:text-md lg:text-lg lg:col-span-full text-slate-800 text-center">
					Please enter in your email address and password to register
				</p>
	            <div class="flex items-center bg-blue-500 rounded-md gap-4 px-4 py-2">
					<label for="email" class="text-slate-50 font-bold">Email</label>
					<input class="bg-slate-50 text-slate-800 rounded" type="email" name="email">
				</div>
	            <div class="flex items-center bg-blue-500 rounded-md gap-4 px-4 py-2">
					<label for="password" class="text-slate-50 font-bold">Password</label>
					<input class="bg-slate-50 text-slate-800 rounded" type="password" name="password">
				</div>
				<input class="lg:col-span-full bg-yellow-100 text-slate-800 px-4 py-2 font-bold rounded-md" type="submit">
			</form>
			<form action="/login" method="POST"
				class="grid justify-items-center xl:grid-cols-2 bg-blue-300 w-full max-w-6xl gap-4 p-8 rounded-md shadow-md shadow-slate-500/20">
				<p class="lg:col-span-full text-red-500 font-bold">%s</p>
				<h2 class="text-xl md:text-2xl lg:text-4xl lg:col-span-full text-slate-50 font-bold text-center">
					Login Now
				</h2>
				<p class="text md:text-md lg:text-lg lg:col-span-full text-slate-800 text-center">
					Please enter in your email address and password to login
				</p>
	            <div class="flex items-center bg-blue-500 rounded-md gap-4 px-4 py-2">
					<label for="email" class="text-slate-50 font-bold">Email</label>
					<input class="bg-slate-50 text-slate-800 rounded" type="email" name="email">
				</div>
	            <div class="flex items-center bg-blue-500 rounded-md gap-4 px-4 py-2">
					<label for="password" class="text-slate-50 font-bold">Password</label>
					<input class="bg-slate-50 text-slate-800 rounded" type="password" name="password">
				</div>
				<input class="lg:col-span-full bg-yellow-100 text-slate-800 px-4 py-2 font-bold rounded-md" type="submit">
			</form>
		</body>
	</html>`, regErrMsg, logErrMsg)
	http.ResponseWriter.Write(w, []byte(html))
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, fmt.Sprintf("/?regerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error in parsing form", http.StatusInternalServerError)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		errorMsg := url.QueryEscape("empty email value")
		http.Redirect(w, r, fmt.Sprintf("/?regerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}
	if _, exists := db[email]; exists {
		errorMsg := url.QueryEscape("account already exists")
		http.Redirect(w, r, fmt.Sprintf("/?regerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		errorMsg := url.QueryEscape("empty password value")
		http.Redirect(w, r, fmt.Sprintf("/?regerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	hPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	db[email] = hPass
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, fmt.Sprintf("/?logerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	loginFail := false

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error in parsing form", http.StatusInternalServerError)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		errorMsg := url.QueryEscape("empty email value")
		http.Redirect(w, r, fmt.Sprintf("/?logerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}
	if _, exists := db[email]; !exists {
		errorMsg := url.QueryEscape("email and password combo failed")
		http.Redirect(w, r, fmt.Sprintf("/?logerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		errorMsg := url.QueryEscape("empty password value")
		http.Redirect(w, r, fmt.Sprintf("/?logerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	err = bcrypt.CompareHashAndPassword(db[email], []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			loginFail = true
		} else {
			http.Error(w, "Internal Sever Error", http.StatusInternalServerError)
		}
	}

	if loginFail {
		errorMsg := url.QueryEscape("email and password combo failed")
		http.Redirect(w, r, fmt.Sprintf("/?logerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Ninja Level 2 Exercise 3</title>
			<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
		</head>
		<body class="flex flex-col gap-20 mx-auto container px-4 pt-10 bg-slate-50">
				<h2 class="text-xl md:text-2xl lg:text-4xl lg:col-span-full text-green-500 font-bold text-center">
		            Login Success, Welcome %s
				</h2>
		</body>
	</html>`, email)
}

func createToken(sessID string) (string, error) {
	h := hmac.New(sha256.New, []byte(key))
	_, err := h.Write([]byte(sessID))
	if err != nil {
		return "", fmt.Errorf("error in createToken: %w", err)
	}

	return fmt.Sprintf("%s|%s", sessID, base64.StdEncoding.EncodeToString(h.Sum(nil))), nil
}

func parseToken(sigStr string) (string, error) {
	xs := strings.SplitN(sigStr, "|", 2)
	if len(xs) < 2 {
		return "", ErrInvalidToken
	}

	sessID := xs[0]
	sig, err := base64.StdEncoding.DecodeString(xs[1])
	if err != nil {
		return "", fmt.Errorf("parseToken: %w", err)
	}

	h := hmac.New(sha256.New, []byte(key))
	_, err = h.Write([]byte(sessID))
	if err != nil {
		return "", fmt.Errorf("error in parseToken: %w", err)
	}

	newSig := h.Sum(nil)
	if !hmac.Equal(newSig, sig) {
		return "", ErrInvalidToken
	}

	return sessID, nil
}
