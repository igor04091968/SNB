package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"snb-worktime-webui/internal/web"
)

func main() {
	addr := os.Getenv("WORKTIME_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:    addr,
		Handler: web.NewHandler(),
	}

	listener, err := listenWithTakeover(addr)
	if err != nil {
		log.Fatal(err)
	}
	pidFile, err := writePIDFile(addr)
	if err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}
	defer func() {
		_ = os.Remove(pidFile)
	}()

	log.Printf("worktime web UI listening on %s", addr)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func listenWithTakeover(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err == nil {
		return listener, nil
	}
	if !strings.Contains(err.Error(), "address already in use") {
		return nil, err
	}

	killed, killErr := killPreviousInstance(addr)
	if killErr != nil {
		return nil, fmt.Errorf("address %s already in use and previous instance was not stopped: %w", addr, killErr)
	}
	if !killed {
		return nil, fmt.Errorf("address %s already in use and no managed previous instance was found", addr)
	}

	for attempt := 0; attempt < 20; attempt++ {
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			return listener, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, err
}

func killPreviousInstance(addr string) (bool, error) {
	pidFile := pidFilePath(addr)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false, err
	}
	if pid <= 0 || pid == os.Getpid() {
		return false, nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}

	if err := terminateProcess(process); err != nil {
		return false, err
	}
	return true, nil
}

func terminateProcess(process *os.Process) error {
	if process == nil {
		return nil
	}

	if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func writePIDFile(addr string) (string, error) {
	pidFile := pidFilePath(addr)
	if err := os.MkdirAll(filepath.Dir(pidFile), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return "", err
	}
	return pidFile, nil
}

func pidFilePath(addr string) string {
	replacer := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	name := replacer.Replace(addr)
	if name == "" {
		name = "default"
	}
	return filepath.Join("state", "runtime", "snb-worktime-webui-"+name+".pid")
}
