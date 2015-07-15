package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/heroku-examples/go-sessions-demo/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/heroku-examples/go-sessions-demo/Godeps/_workspace/src/github.com/codegangsta/negroni"
	"github.com/heroku-examples/go-sessions-demo/Godeps/_workspace/src/github.com/gorilla/sessions"
)

const (
	//SessionName to store session under
	SessionName = "go-sessions-demo"
)

var sessionStore sessions.Store

func handleSessionError(w http.ResponseWriter, err error) {
	log.WithField("err", err).Info("Error handling session.")
	http.Error(w, "Application Error", http.StatusInternalServerError)
}

func home(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, SessionName)
	if err != nil {
		handleSessionError(w, err)
		return
	}

	username := session.Values["username"]
	if u, ok := username.(string); !ok || u == "" {
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		log.WithField("username", u).Info("Username == '', redirecting")
		return
	}

	w.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body>Hello %s<br/><a href='/logout'>Logout</a></body></html>", username)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	log.WithFields(log.Fields{"username": username, "password": password}).Info("Received login request.")

	// These would probably be looked up in a DB or environment normally
	if username == "foo" && password == "secret" {
		session, err := sessionStore.Get(r, SessionName)
		if err != nil {
			handleSessionError(w, err)
			return
		}

		session.Values["username"] = username
		if err := session.Save(r, w); err != nil {
			handleSessionError(w, err)
			return
		}

		log.WithField("username", username).Info("completed login & session.Save")
	}

	http.Redirect(w, r, "/", 303)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, SessionName)
	if err != nil {
		handleSessionError(w, err)
		return
	}

	session.Values["username"] = ""
	if err := session.Save(r, w); err != nil {
		handleSessionError(w, err)
		return
	}

	log.WithField("username", "").Info("completed logout & session.Save")
	http.Redirect(w, r, "/", 302)
}

// determineEncryptionKey ensures the provided SESSION_ENCRYPTION_KEY is the
// correct size (16, 24 or 32 bytes). If it's too large it's truncated to the
// max. If it's otherwise incorrect size wise an error is returned. Otherwise
// the []byte version is returned.
func determineEncryptionKey() ([]byte, error) {
	sek := os.Getenv("SESSION_ENCRYPTION_KEY")
	lek := len(sek)
	switch {
	case lek >= 0 && lek < 16, lek > 16 && lek < 24, lek > 24 && lek < 32:
		return nil, fmt.Errorf("SESSION_ENCRYPTION_KEY needs to be either 16, 24 or 32 characters long or longer, was: %d", lek)
	case lek == 16, lek == 24, lek == 32:
		return []byte(sek), nil
	case lek > 32:
		return []byte(sek[0:32]), nil
	default:
		panic("Should not get here.")
	}

}

func main() {
	ek, err := determineEncryptionKey()
	if err != nil {
		log.Fatal(err)
	}
	sessionStore = sessions.NewCookieStore(
		[]byte(os.Getenv("SESSION_AUTHENTICATION_KEY")),
		ek,
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/", home)

	n := negroni.Classic()

	port := os.Getenv("PORT")
	if port == "" {
		log.WithField("PORT", port).Fatal("$PORT must be set")
	}
	n.Run(":" + port)
}
