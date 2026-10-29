package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Note struct {
	ID      int
	Content string
}

type User struct {
	ID       int
	Username string
}

type PageData struct {
	Title    string
	Username string
	Notes    []Note
}

func render(w http.ResponseWriter, name string, data any) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Println(err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var templates = template.Must(template.ParseGlob("templates/*.html"))
var db *sql.DB

func home(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT id, content FROM notes WHERE user_id = ? ORDER BY id DESC", user.ID)
	if err != nil {
		log.Println(err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Content); err != nil {
			log.Println(err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		notes = append(notes, n)
	}
	if err := rows.Err(); err != nil {
		log.Println(err)
		http.Error(w, "db error", http.StatusInternalServerError)
	}

	render(w, "index.html", PageData{Title: "Notes App", Username: user.Username, Notes: notes})
}

func createNote(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	_, err := db.Exec("INSERT INTO notes (user_id, content) VALUES (?, ?)", user.ID, r.FormValue("note"))
	if err != nil {
		log.Println(err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func currentUser(r *http.Request) *User {
	c, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	var u User
	err = db.QueryRow(`
		SELECT users.id, users.username
		from sessions JOIN users on users.id = sessions.user_id
		WHERE sessions.token = ?
	`, c.Value).Scan(&u.ID, &u.Username)
	if err != nil {
		return nil
	}
	return &u
}

func registerGet(w http.ResponseWriter, r *http.Request) {
	render(w, "register.html", PageData{Title: "Register new user"})
}

func registerPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || len(password) < 8 {
		http.Error(w, "username required, password minimum 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		http.Error(w, "Username taken", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginGet(w http.ResponseWriter, r *http.Request) {
	render(w, "login.html", PageData{Title: "Log in"})
}

func loginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	var hash string

	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&id, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := newToken()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("INSERT INTO sessions (token, user_id) VALUES (?, ?)", token, id); err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, token)
	log.Println("new seesion for user:", username)
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		db.Exec("DELETE FROM sessions WHERE token = ?", c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "app.db"
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	schema := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			content TEXT NOT NULL)`,
	}
	for _, table := range schema {
		if _, err := db.Exec(table); err != nil {
			log.Fatal(err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", home)
	mux.HandleFunc("POST /notes", createNote)
	mux.HandleFunc("GET /register", registerGet)
	mux.HandleFunc("POST /register", registerPost)
	mux.HandleFunc("GET /login", loginGet)
	mux.HandleFunc("POST /login", loginPost)
	mux.HandleFunc("POST /logout", logout)
	// mux.Handle("GET /static/", http.FileServer(http.Dir(".")))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("We listening on port :3000")

	srv := &http.Server{
		Addr:    ":3000",
		Handler: logging(mux),
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				log.Println("new connection from", c.RemoteAddr())
			}
		},
	}
	log.Fatal(srv.ListenAndServe())
}
