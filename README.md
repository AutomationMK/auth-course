# Web Authentication With Golang

## Description

This is a project following along udemy course Web Authentication With Golang

## Getting Started
First you need to create a .env file in order to run
the Github oauth2 test in oauth2/oauth2.go file.
To be able to run your that file, you first you need to go to your github /settings/profile when logged in. Then navigate to developer settings and OAuth Apps tab where you can set up your own example application. Since this will run on your local computer your host needs to be setup as http://localhost:(your port number)

Your .env file will just need two variables like so...
`GITHUB_CLIENT_ID=(your app client id on github)
GITHUB_CLIENT_SECRET=(your app client secret on github)`

I personally use linux so you need to research how to add
OS level environment variables from a .env file.

But on Linux you run the following bash script in your shell terminal...
`export $(cat .env | xargs)`

from there your environment variables will be available and you can run the oauth2.go file

### Dependencies
* [UUID](https://github.com/gofrs/uuid) v5.4.0 (for generating unique IDs)
* [JWT](https://github.com/golang-jwt/jwt) v5.3.1 (for using JWT token creation)
* [Crypto](https://golang.org/x/crypto) v0.50.0 (for encryption algorithms)
* [OAuth2](https://golang.org/x/oauth2) v0.36.0 (for OAuth2 usage)

### Installing manually

No install is required other than performing...
`go mod tidy`
to install needed dependencies

All files can be run separately by typing command...
`go run (file path)`

### Authors

Max Kranker

## Version History

* v0.1.0
  * Initial pre-release
* v0.2.0
  * Json Marshal Example
* v0.3.0
  * Unmarshal Example
* v0.4.0
  * Set Up Server
* v0.5.0
  * Encode Example
* v0.6.0
  * Decode Example
* v0.7.0
  * Ninja Level 1 Excercise 1
* v0.8.0
  * Ninja Level 1 Exercise 2
* v0.9.0
  * HTTP Header Basic Authentication
* v0.10.0
  * Password Hash Example
* v0.11.0
  * HMAC Hashing
* v0.12.0
  * JWT Custom Claims
* v0.13.0
  * createTag Method
* v0.14.0
  * parseToken Helper Function
* v0.15.0
  * Rotating Keys
* v0.16.0
  * AES Encryption Example
* v0.17.0
  * Improved AES Encryption
* v0.18.0
  * HMAC Authorization
* v0.19.0
  * JWT Authentication
* v0.20.0
  * Ninja Level 2 Exercise 1
* v0.20.1
  * Move Ex1 Into Separate Dir
* v0.21.0
  * Ninja Level 2 Exercise 2
* v0.22.0
  * Ninja Level 2 Excercise 3
* v0.22.1
  * Fix HTML title Exercise Numbers
* v0.23.0
  * Ninja Level 2 Exercise 4
* v0.24.0
  * Ninja Level 2 Exercise 5
* v0.25.0
  * Ninja Level 2 Exercise 6
* v0.26.0
  * Initial Github Oauth2 Test
* v0.27.0
  * Fully Updated README

## License

See the LICENSE.md file for details
