package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type userClaims struct {
	jwt.RegisteredClaims
	UserData UserData `json:"user-data"`
}

type UserData struct {
	Email       string `json:"email"`
	FirstName   string `json:"first-name"`
	LastName    string `json:"last-name"`
	AccessLevel int    `json:"access-level"`
}

type User struct {
	UserData UserData `json:"user-data"`
	Password string   `json:"password"`
}

var db = make(map[string]User)
var key = "secretKey"

var ErrInvalidToken = errors.New("parseToken invalid token")
var ErrWrongSigningMethod = errors.New("parseToken wrong signing method")

func main() {
	http.HandleFunc("/", register)
	http.HandleFunc("/register", postRegister)
	http.HandleFunc("/login", postLogin)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	invldTknMsg := ""
	invldSess := false
	var userClaims = &userClaims{}

	// get session token
	sessTkn, err := r.Cookie("session")
	if err != nil {
		invldSess = true
	} else {
		// if session token exists then get session ID
		userClaims, err = parseToken(sessTkn.Value)
		if err != nil {
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
			invldSess = true
		}
	}

	if invldSess {
		regErrMsg := r.URL.Query().Get("regerrmsg")
		logErrMsg := r.URL.Query().Get("logerrmsg")
		html := fmt.Sprintf(`<!DOCTYPE html>
		<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>Ninja Level 2 Exercise 6</title>
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
		http.ResponseWriter.Write(w, []byte(html))
		return
	}

	user := userClaims.UserData
	msg := fmt.Sprintf("Welcome %s!", user.FirstName)

	html := fmt.Sprintf(`<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Ninja Level 2 Exercise 6</title>
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
		UserData: UserData{
			Email:       email,
			FirstName:   firstName,
			LastName:    lastName,
			AccessLevel: 2,
		},
		Password: string(hPass),
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

	err = bcrypt.CompareHashAndPassword([]byte(db[email].Password), []byte(password))
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

	userData := db[email].UserData

	token, err := createToken(userData)
	if err != nil {
		http.Error(w, "Error in creating token", http.StatusInternalServerError)
		log.Printf("%s", err)
		return
	}

	c := http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 2),
		HttpOnly: true,
	}
	http.SetCookie(w, &c)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func createToken(userData UserData) (string, error) {
	claims := userClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 2)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		UserData: userData,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)

	sigStr, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("Error in createToken: %w", err)
	}

	return sigStr, nil
}

func parseToken(sigStr string) (*userClaims, error) {
	vrfyTok, err := jwt.ParseWithClaims(sigStr, &userClaims{}, func(unvrfyTok *jwt.Token) (any, error) {
		if unvrfyTok.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, ErrWrongSigningMethod
		}
		return []byte(key), nil
	})
	if err != nil {
		return nil, err
	}

	if !vrfyTok.Valid {
		return nil, ErrInvalidToken
	}

	return vrfyTok.Claims.(*userClaims), nil
}
