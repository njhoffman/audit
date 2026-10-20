// Package taskserver serves the tasks page on localhost with an API that
// saves status and note changes. Every request must carry the per-run token
// audit printed, and the Host header must name a loopback address, so other
// local users and web pages (including DNS rebinding) cannot read or change
// tasks.
package taskserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/njhoffman/audit/internal/htmlreport"
	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

// Backend reads and changes tasks; an unknown id is an error matching
// store.ErrNoTask.
type Backend interface {
	Todos(ctx context.Context) ([]todo.Todo, error)
	SetStatus(ctx context.Context, id int64, s todo.Status) (todo.Todo, error)
	SetNote(ctx context.Context, id int64, note string) (todo.Todo, error)
}

// TokenHeader carries the token on API requests.
const TokenHeader = "X-Audit-Token" // #nosec G101 -- a header name, not a credential

// maxBody bounds a change request.
const maxBody = 64 << 10

// Server is the tasks page and its API.
type Server struct {
	B     Backend
	Token string
	Host  string
	Now   func() time.Time
}

// NewToken returns a random token for one server run.
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Handler routes the page and the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /api/tasks", s.list)
	mux.HandleFunc("POST /api/tasks/{id}", s.change)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		if !loopback(r.Host) {
			http.Error(w, "audit only answers requests to 127.0.0.1 or localhost", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// loopback reports whether a Host header names this machine's loopback.
func loopback(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) tokenOK(given string) bool {
	return given != "" && subtle.ConstantTimeCompare([]byte(given), []byte(s.Token)) == 1
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if !s.tokenOK(r.URL.Query().Get("token")) {
		http.Error(w, "missing or wrong token: open the URL audit todo --serve printed", http.StatusForbidden)
		return
	}
	ts, err := s.B.Todos(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := htmlreport.WriteTasks(w, htmlreport.TasksPage{Tasks: ts, Host: s.Host, Now: s.Now(), Token: s.Token}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	if !s.tokenOK(r.Header.Get(TokenHeader)) {
		http.Error(w, "missing or wrong token", http.StatusForbidden)
		return
	}
	ts, err := s.B.Todos(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ts == nil {
		ts = []todo.Todo{}
	}
	writeJSON(w, ts)
}

// Change is the body of a change request; absent fields stay as they are.
type Change struct {
	Status *string `json:"status"`
	Note   *string `json:"note"`
}

func (s *Server) change(w http.ResponseWriter, r *http.Request) {
	if !s.tokenOK(r.Header.Get(TokenHeader)) {
		http.Error(w, "missing or wrong token", http.StatusForbidden)
		return
	}
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	var c Change
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if c.Status == nil && c.Note == nil {
		http.Error(w, "nothing to change: send status or note", http.StatusBadRequest)
		return
	}
	var t todo.Todo
	if c.Status != nil {
		st, err := todo.ParseStatus(*c.Status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if t, err = s.B.SetStatus(r.Context(), id, st); err != nil {
			fail(w, err)
			return
		}
	}
	if c.Note != nil {
		if t, err = s.B.SetNote(r.Context(), id, *c.Note); err != nil {
			fail(w, err)
			return
		}
	}
	writeJSON(w, t)
}

func fail(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, store.ErrNoTask) {
		code = http.StatusNotFound
	}
	http.Error(w, err.Error(), code)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
