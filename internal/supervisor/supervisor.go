// Package supervisor runs child processes, restarts them when they exit
// and forwards their output to the structured log.
package supervisor

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"vpngw/internal/logx"
)

// Process is a supervised child process.
type Process struct {
	Name string
	// Command builds a fresh command for every start.
	Command func() *exec.Cmd
	// BeforeStart runs before each start (e.g. to render configs).
	BeforeStart func() error

	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	pid       int
	restarts  int
	startedAt time.Time
	lastExit  string
	lastLines []string
	stopped   bool
	restart   chan struct{}
	done      chan struct{}
}

// Status describes the process state.
type Status struct {
	Name      string
	Running   bool
	PID       int
	Restarts  int
	StartedAt time.Time
	LastExit  string
	LastLines []string
}

// Status returns the current state.
func (p *Process) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{Name: p.Name, Running: p.running, PID: p.pid, Restarts: p.restarts, StartedAt: p.startedAt,
		LastExit: p.lastExit, LastLines: append([]string(nil), p.lastLines...)}
}

// Run supervises the process until ctx is cancelled.
func (p *Process) Run(ctx context.Context) {
	p.mu.Lock()
	p.restart = make(chan struct{}, 1)
	p.done = make(chan struct{})
	p.mu.Unlock()
	defer close(p.done)
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := p.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		stopped := p.stopped
		p.mu.Unlock()
		if stopped {
			select {
			case <-ctx.Done():
				return
			case <-p.restart:
				p.mu.Lock()
				p.stopped = false
				p.mu.Unlock()
				continue
			}
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		slog.Warn("process exited, restarting", "proc", p.Name, "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		case <-p.restart:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		p.mu.Lock()
		p.restarts++
		p.mu.Unlock()
	}
}

func (p *Process) runOnce(ctx context.Context) error {
	if p.BeforeStart != nil {
		if err := p.BeforeStart(); err != nil {
			p.setExit("prepare: " + err.Error())
			return err
		}
	}
	cmd := p.Command()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		p.setExit("start: " + err.Error())
		return err
	}
	p.mu.Lock()
	p.cmd, p.running, p.pid, p.startedAt = cmd, true, cmd.Process.Pid, time.Now()
	p.mu.Unlock()
	slog.Info("process started", "proc", p.Name, "pid", cmd.Process.Pid)
	var wg sync.WaitGroup
	wg.Add(2)
	go p.pump(stdout, &wg)
	go p.pump(stderr, &wg)
	waitErr := make(chan error, 1)
	go func() {
		wg.Wait()
		waitErr <- cmd.Wait()
	}()
	var err error
	select {
	case err = <-waitErr:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case err = <-waitErr:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			err = <-waitErr
		}
	}
	msg := "exited"
	if err != nil {
		msg = err.Error()
	}
	p.setExit(msg)
	return err
}

func (p *Process) setExit(msg string) {
	p.mu.Lock()
	p.running = false
	p.pid = 0
	p.lastExit = time.Now().UTC().Format(time.RFC3339) + " " + msg
	p.mu.Unlock()
}

func (p *Process) pump(r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := logx.Scrub(strings.TrimSpace(sc.Text()))
		if line == "" {
			continue
		}
		p.mu.Lock()
		p.lastLines = append(p.lastLines, line)
		if len(p.lastLines) > 200 {
			p.lastLines = p.lastLines[len(p.lastLines)-200:]
		}
		p.mu.Unlock()
		slog.Info(line, "proc", p.Name)
	}
}

// Restart terminates the process; Run starts it again immediately.
func (p *Process) Restart() {
	p.mu.Lock()
	cmd := p.cmd
	running := p.running
	p.stopped = false
	ch := p.restart
	p.mu.Unlock()
	if running && cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Signal sends a signal to the process (e.g. SIGHUP to reload).
func (p *Process) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	cmd := p.cmd
	running := p.running
	p.mu.Unlock()
	if !running || cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(sig)
}

// Running reports whether the process is up.
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}
