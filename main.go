package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

const (
	//SessionName to store session under
	SessionName = "go-sessions-demo"
)

var (
	sessionStore sessions.Store
	log          = logrus.WithField("cmd", "go-sessions-demo")
)

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

	username, found := session.Values["username"]
	if !found || username == "" {
		http.Redirect(w, r, "/public/login.html", http.StatusSeeOther)
		log.WithField("username", username).Info("Username is empty/notfound, redirecting")
		return
	}

	w.Header().Add("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body>Hello %s<br/><a href='/logout'>Logout</a></body></html>", username)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	log.WithFields(logrus.Fields{"username": username, "password": password}).Info("Received login request.")

	// Normally, these would probably be looked up in a DB or environment
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

	log.Info("completed logout & session.Save")
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
		return nil, errors.Errorf("SESSION_ENCRYPTION_KEY needs to be either 16, 24 or 32 characters long or longer, was: %d", lek)
	case lek == 16, lek == 24, lek == 32:
		return []byte(sek), nil
	case lek > 32:
		return []byte(sek[0:32]), nil
	default:
		return nil, errors.New("invalid SESSION_ENCRYPTION_KEY: " + sek)
	}

}

func main() {
	ek, err := determineEncryptionKey()
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		log.WithField("PORT", port).Fatal("$PORT must be set")
	}

	sessionStore = sessions.NewCookieStore(
		[]byte(os.Getenv("SESSION_AUTHENTICATION_KEY")),
		ek,
	)

	http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/", home)

	log.Println(http.ListenAndServe(":"+port, nil))
}
