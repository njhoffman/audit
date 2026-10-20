package taskserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/njhoffman/audit/internal/store"
	"github.com/njhoffman/audit/internal/todo"
)

type fake struct {
	mu    sync.Mutex
	tasks map[int64]todo.Todo
}

func (f *fake) Todos(context.Context) ([]todo.Todo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []todo.Todo
	for _, t := range f.tasks {
		out = append(out, t)
	}
	return out, nil
}

func (f *fake) get(id int64) (todo.Todo, error) {
	t, ok := f.tasks[id]
	if !ok {
		return t, store.ErrNoTask
	}
	return t, nil
}

func (f *fake) SetStatus(_ context.Context, id int64, s todo.Status) (todo.Todo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, err := f.get(id)
	if err != nil {
		return t, err
	}
	t.Status = s
	f.tasks[id] = t
	return t, nil
}

func (f *fake) SetNote(_ context.Context, id int64, note string) (todo.Todo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, err := f.get(id)
	if err != nil {
		return t, err
	}
	t.Note = note
	f.tasks[id] = t
	return t, nil
}

const token = "0123456789abcdef"

func setup() (*fake, http.Handler) {
	f := &fake{tasks: map[int64]todo.Todo{7: {ID: 7, Command: "scripts", Title: "Fix shellcheck errors in 3 scripts",
		Priority: todo.High, Status: todo.Open}}}
	s := &Server{B: f, Token: token, Host: "box", Now: func() time.Time { return time.Unix(0, 0) }}
	return f, s.Handler()
}

func do(h http.Handler, method, target, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1:4321"
	for k, v := range header {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestPageNeedsToken(t *testing.T) {
	_, h := setup()
	if w := do(h, "GET", "/", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("no token: %d", w.Code)
	}
	if w := do(h, "GET", "/?token=wrong", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("wrong token: %d", w.Code)
	}
	w := do(h, "GET", "/?token="+token, "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Fix shellcheck errors in 3 scripts") ||
		!strings.Contains(w.Body.String(), `"`+token+`"`) {
		t.Fatalf("page: %d\n%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers %v", w.Header())
	}
}

func TestRejectsForeignHost(t *testing.T) {
	_, h := setup()
	for _, host := range []string{"evil.example:4321", "192.168.1.5:4321", "127.0.0.1.evil.example"} {
		if w := do(h, "GET", "/?token="+token, "", map[string]string{"Host": host}); w.Code != http.StatusForbidden {
			t.Errorf("host %s: %d", host, w.Code)
		}
	}
	for _, host := range []string{"localhost:4321", "[::1]:4321", "127.0.0.1"} {
		if w := do(h, "GET", "/?token="+token, "", map[string]string{"Host": host}); w.Code != http.StatusOK {
			t.Errorf("host %s: %d", host, w.Code)
		}
	}
}

func TestList(t *testing.T) {
	_, h := setup()
	if w := do(h, "GET", "/api/tasks", "", nil); w.Code != http.StatusForbidden {
		t.Errorf("list without token: %d", w.Code)
	}
	w := do(h, "GET", "/api/tasks", "", map[string]string{TokenHeader: token})
	var ts []todo.Todo
	if err := json.Unmarshal(w.Body.Bytes(), &ts); err != nil || len(ts) != 1 || ts[0].ID != 7 {
		t.Errorf("list: %d %s", w.Code, w.Body.String())
	}
}

func TestChange(t *testing.T) {
	f, h := setup()
	auth := map[string]string{TokenHeader: token, "Origin": "http://127.0.0.1:4321"}

	w := do(h, "POST", "/api/tasks/7", `{"status":"in-progress","note":"halfway"}`, auth)
	var got todo.Todo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if got.Status != todo.InProgress || got.Note != "halfway" || f.tasks[7].Status != todo.InProgress {
		t.Errorf("saved %+v", f.tasks[7])
	}
	w = do(h, "POST", "/api/tasks/7", `{"note":""}`, auth)
	if w.Code != http.StatusOK || f.tasks[7].Note != "" || f.tasks[7].Status != todo.InProgress {
		t.Errorf("note only: %d %+v", w.Code, f.tasks[7])
	}

	cases := []struct {
		name   string
		target string
		body   string
		header map[string]string
		code   int
	}{
		{"no token", "/api/tasks/7", `{"status":"done"}`, map[string]string{}, http.StatusForbidden},
		{"wrong token", "/api/tasks/7", `{"status":"done"}`, map[string]string{TokenHeader: "nope"}, http.StatusForbidden},
		{"token in query only", "/api/tasks/7?token=" + token, `{"status":"done"}`, map[string]string{}, http.StatusForbidden},
		{"cross origin", "/api/tasks/7", `{"status":"done"}`, map[string]string{TokenHeader: token, "Origin": "https://evil.example"}, http.StatusForbidden},
		{"bad status", "/api/tasks/7", `{"status":"finished"}`, auth, http.StatusBadRequest},
		{"empty change", "/api/tasks/7", `{}`, auth, http.StatusBadRequest},
		{"unknown field", "/api/tasks/7", `{"priority":"low"}`, auth, http.StatusBadRequest},
		{"not json", "/api/tasks/7", `status=done`, auth, http.StatusBadRequest},
		{"bad id", "/api/tasks/x", `{"status":"done"}`, auth, http.StatusBadRequest},
		{"unknown id", "/api/tasks/99", `{"status":"done"}`, auth, http.StatusNotFound},
	}
	for _, c := range cases {
		if w := do(h, "POST", c.target, c.body, c.header); w.Code != c.code {
			t.Errorf("%s: got %d want %d (%s)", c.name, w.Code, c.code, w.Body.String())
		}
	}
	if f.tasks[7].Status != todo.InProgress {
		t.Errorf("a refused request changed the task: %+v", f.tasks[7])
	}
	if w := do(h, "GET", "/api/tasks/7", "", auth); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on a change endpoint: %d", w.Code)
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	b, _ := NewToken()
	if err != nil || len(a) != 32 || a == b {
		t.Errorf("tokens %q %q %v", a, b, err)
	}
}
