package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type User struct {
	ID        string `json:"id"`
	Login     string `json:"login,omitempty"`
	Company   string `json:"company,omitempty"`
	Email     string `json:"email,omitempty"`
	AvatarURL string `json:"avatarUrl,omitempty"`
	Bio       string `json:"bio,omitempty"`
}

type githubResponse struct {
	Data struct {
		User User `json:"viewer"`
	} `json:"data"`
}

var githubOauthConfig = &oauth2.Config{
	ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
	ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
	Scopes:       []string{"read:user"},
	Endpoint:     github.Endpoint,
}

type userClaims struct {
	jwt.RegisteredClaims
	User User `json:"user"`
}

// key is github ID, value is user ID
var dbUsr = make(map[string]User)
var key = "secretKey"

var ErrInvalidToken = errors.New("parseToken invalid token")
var ErrWrongSigningMethod = errors.New("parseToken wrong signing method")

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth2/receive", completeGithubOauth)
	http.ListenAndServe(":8080", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
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
				<form action="/oauth/github" method="POST"
					class="grid justify-items-center xl:grid-cols-2 bg-blue-300 w-full max-w-6xl gap-4 p-8 rounded-md shadow-md shadow-slate-500/20">
					<h2 class="text-xl md:text-2xl lg:text-4xl lg:col-span-full text-slate-50 font-bold text-center">
						Login Now
					</h2>
					<input class="lg:col-span-full bg-yellow-100 text-slate-800 px-4 py-2 font-bold rounded-md" type="submit" value="Login with Github">
				</form>
			</body>
		</html>`, invldTknMsg)
		http.ResponseWriter.Write(w, []byte(html))
		return
	}

	usr := userClaims.User
	msg := fmt.Sprintf("Welcome %s!", usr.Login)

	html := fmt.Sprintf(`<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Ninja Level 2 Exercise 6</title>
			<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
		</head>
		<body class="grid lg:grid-cols-2 items-center justify-items-center gap-6 mx-auto container px-4 pt-10 bg-slate-50">
			<h2 class="text-xl md:text-2xl lg:text-4xl text-blue-500 font-bold text-center">
				%s
			</h2>
			<img src="%s" class="w-100 rounded-full">
			<p class="md:text-lg lg:text-xl text-slate-50 px-6 py-4 w-full bg-blue-300">Email: %s</p>
			<p class="md:text-lg lg:text-xl text-slate-50 px-6 py-4 w-full bg-blue-300">Company: %s</p>
			<h3 class="lg:col-span-full text-xl md:text-2xl lg:text-4xl text-blue-500 font-bold text-center">
				%s
			</h3>
		</body>
	</html>`, msg, usr.AvatarURL, usr.Email, usr.Company, usr.Bio)
	http.ResponseWriter.Write(w, []byte(html))
}

func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if state != "0000" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	tokenSrc := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), tokenSrc)

	requestBody := strings.NewReader(`{"query": "query {viewer {id login company email avatarUrl bio}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var gitResp githubResponse
	err = json.NewDecoder(resp.Body).Decode(&gitResp)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	githubID := gitResp.Data.User.ID
	usr, ok := dbUsr[githubID]
	if !ok {
		// new user create account
		dbUsr[githubID] = gitResp.Data.User
		usr = dbUsr[githubID]
	}

	// login to account using jwt
	signTokn, err := createToken(usr)
	if err != nil {
		http.Error(w, "Error in creating token", http.StatusInternalServerError)
		log.Printf("%s", err)
		return
	}

	c := http.Cookie{
		Name:     "session",
		Value:    signTokn,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 2),
		HttpOnly: true,
	}
	http.SetCookie(w, &c)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func createToken(usr User) (string, error) {
	claims := userClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 2)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		User: usr,
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
