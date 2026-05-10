package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

var db = make(map[string][]byte)

func main() {
	http.HandleFunc("/", register)
	http.HandleFunc("/register", postRegister)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	errorMessage := r.URL.Query().Get("errormsg")
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title>Ninja Level 2 Exercise 1</title>
			<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
		</head>
		<body class="mx-auto container px-4 pt-10 bg-slate-50">
			<form action="/register" method="POST"
				class="grid justify-items-center xl:grid-cols-2 bg-blue-300 w-full max-w-6xl gap-4 p-8 rounded-md shadow-md shadow-slate-500/20">
		        <p class="text-red-500 font-bold">%s</p>
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
		</body>
	</html>`, errorMessage)
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, fmt.Sprintf("/?errormsg=%s", errorMsg), http.StatusSeeOther)
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
		http.Redirect(w, r, fmt.Sprintf("/?errormsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		errorMsg := url.QueryEscape("empty password value")
		http.Redirect(w, r, fmt.Sprintf("/?errormsg=%s", errorMsg), http.StatusSeeOther)
		return
	}

	hPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	db[password] = hPass
	log.Println(db)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
