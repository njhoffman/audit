package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/njhoffman/audit/internal/htmlreport"
	"github.com/njhoffman/audit/internal/taskserver"
)

// tasksPath is the tasks page inside the report directory.
func (a *app) tasksPath() string { return filepath.Join(a.cfg.ReportDir(), htmlreport.TasksFile) }

// tasksLink is the index's link to the tasks page, "" until it is written.
func (a *app) tasksLink() string {
	if _, err := os.Stat(a.tasksPath()); err != nil {
		return ""
	}
	return htmlreport.TasksFile
}

// writeTasksPage writes the static tasks page with every task and returns
// its path.
func (a *app) writeTasksPage(ctx context.Context) (string, error) {
	ts, err := a.store.Todos(ctx, "")
	if err != nil {
		return "", err
	}
	path := a.tasksPath()
	err = htmlreport.Save(path, func(w io.Writer) error {
		return htmlreport.WriteTasks(w, htmlreport.TasksPage{Tasks: ts, Host: a.engine.Host, Now: timeNow()})
	})
	if err != nil {
		return "", fmt.Errorf("write tasks page: %w", err)
	}
	return path, nil
}

// serveTasks serves the live tasks page on 127.0.0.1:port until ctx ends.
// ready, when set, receives the page URL once the server listens.
func (a *app) serveTasks(ctx context.Context, port int, open bool, ready func(string)) error {
	token, err := taskserver.NewToken()
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("listen on 127.0.0.1:%d: %w", port, err)
	}
	srv := &http.Server{
		Handler:           (&taskserver.Server{B: tuiBackend{a}, Token: token, Host: a.engine.Host, Now: timeNow}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	url := fmt.Sprintf("http://%s/?token=%s", ln.Addr(), token)
	sayln(a.errOut, "serving tasks at "+url)
	sayln(a.errOut, "changes are saved as you make them; press ctrl+c to stop")
	if ready != nil {
		ready(url)
	}
	if open {
		if err := a.opener(url); err != nil {
			a.log.Warn("open browser", "err", err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
