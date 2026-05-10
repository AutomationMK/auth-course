package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email       string
	FirstName   string
	LastName    string
	AccessLevel int
	Password    []byte
}

var db = make(map[string]User)
var sessions = make(map[string]string)
var key = "secretKey"

var ErrInvalidToken = errors.New("parseToken invalid token")

func main() {
	http.HandleFunc("/", register)
	http.HandleFunc("/register", postRegister)
	http.HandleFunc("/login", postLogin)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	invldTknMsg := ""
	sessID := ""

	// get session token
	sessTkn, err := r.Cookie("session")
	if err != nil {
		sessTkn = &http.Cookie{}
	} else {
		// if session token exists then get session ID
		sessID, err = parseToken(sessTkn.Value)
		if err != nil {
			if errors.Is(err, ErrInvalidToken) {
				invldTknMsg = "Invalid session Token"
				// delete invalid session cookie
				c := http.Cookie{
					Name:     "session",
					Value:    "",
					Path:     "/",
					Expires:  time.Unix(0, 0),
					HttpOnly: true,
				}
				http.SetCookie(w, &c)
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				log.Println(err)
				return
			}
		}
	}

	html := ""
	if sessID == "" {
		regErrMsg := r.URL.Query().Get("regerrmsg")
		logErrMsg := r.URL.Query().Get("logerrmsg")
		html = fmt.Sprintf(`<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>Ninja Level 2 Exercise 5</title>
				<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
			</head>
			<body class="flex flex-col items-center gap-20 mx-auto container px-4 pt-10 bg-slate-50">
				<h2 class="text-xl md:text-2xl lg:text-4xl lg:col-span-full text-red-500 font-bold text-center">
					%s
				</h2>
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
						<label for="first_name" class="text-slate-50 font-bold">First Name</label>
						<input class="bg-slate-50 text-slate-800 rounded" type="text" name="first_name">
					</div>
					<div class="flex items-center bg-blue-500 rounded-md gap-4 px-4 py-2">
						<label for="last_name" class="text-slate-50 font-bold">Last Name</label>
						<input class="bg-slate-50 text-slate-800 rounded" type="text" name="last_name">
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
		</html>`, invldTknMsg, regErrMsg, logErrMsg)
	} else {
		msg := ""
		user := User{}
		if _, ok := sessions[sessID]; !ok {
			msg = "Missing Session Data"
		} else {
			user = db[sessions[sessID]]
			msg = fmt.Sprintf("Welcome %s!", user.FirstName)
		}
		html = fmt.Sprintf(`<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>Ninja Level 2 Exercise 5</title>
				<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
			</head>
			<body class="flex flex-col items-center gap-20 mx-auto container px-4 pt-10 bg-slate-50">
				<h2 class="text-xl md:text-2xl lg:text-4xl text-blue-500 font-bold text-center">
					%s
				</h2>
				<p class="md:text-lg lg:text-xl text-slate-800">First Name: %s</p>
				<p class="md:text-lg lg:text-xl text-slate-800">Last Name: %s</p>
				<p class="md:text-lg lg:text-xl text-slate-800">Acces Level: %d</p>
			</body>
		</html>`, msg, user.FirstName, user.LastName, user.AccessLevel)
	}
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

	firstName := r.FormValue("first_name")
	if firstName == "" {
		errorMsg := url.QueryEscape("empty first name value")
		http.Redirect(w, r, fmt.Sprintf("/?regerrmsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	lastName := r.FormValue("last_name")
	if lastName == "" {
		errorMsg := url.QueryEscape("empty last name value")
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

	db[email] = User{
		Email:       email,
		FirstName:   firstName,
		LastName:    lastName,
		AccessLevel: 2,
		Password:    hPass,
	}
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

	err = bcrypt.CompareHashAndPassword(db[email].Password, []byte(password))
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

	// generate a random session ID
	uid, err := uuid.NewV7()
	if err != nil {
		http.Error(w, "Error in generating session ID", http.StatusInternalServerError)
		log.Printf("%s", err)
		return
	}
	sessID := uid.String()
	sessions[sessID] = email

	token, err := createToken(sessID)
	if err != nil {
		http.Error(w, "Error in creating token", http.StatusInternalServerError)
		log.Printf("%s", err)
		return
	}

	c := http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 5),
		HttpOnly: true,
	}
	http.SetCookie(w, &c)

	http.Redirect(w, r, "/", http.StatusSeeOther)
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
