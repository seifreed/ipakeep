package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"

	"github.com/majd/ipatool/v2/internal/storeauth"
)

const maxStateSize = 1 << 20

type response struct {
	Headers map[string]string `json:"headers"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find user config directory: %w", err)
	}
	statePath := filepath.Join(configDir, "ipakeep", "anisette-v4.json")
	if err = ensurePrivateDirectory(filepath.Dir(statePath)); err != nil {
		return err
	}

	lock, err := lockState(statePath + ".lock")
	if err != nil {
		return err
	}
	defer unlockState(lock)

	if len(os.Args) > 1 && os.Args[1] == "login" {
		return runLogin(statePath, os.Stdin, os.Stdout)
	}

	state, err := readState(statePath)
	if err != nil {
		return err
	}
	headers, updatedState, err := storeauth.AnisetteHeaders(context.Background(), http.DefaultClient, state)
	if err != nil {
		return fmt.Errorf("generate local Apple Anisette: %w", err)
	}
	if err = writeState(statePath, updatedState); err != nil {
		return err
	}
	flatHeaders, err := flattenHeaders(headers)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(response{Headers: flatHeaders})
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create anisette state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect anisette state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("anisette state path is not a real directory")
	}
	if err = os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure anisette state directory: %w", err)
	}
	return nil
}

func flattenHeaders(headers http.Header) (map[string]string, error) {
	flat := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) != 1 || values[0] == "" {
			return nil, fmt.Errorf("Apple generated an invalid %s header", key)
		}
		flat[key] = values[0]
	}
	return flat, nil
}

func lockState(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open anisette state lock: %w", err)
	}
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure anisette state lock: %w", err)
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock anisette state: %w", err)
	}
	return file, nil
}

func unlockState(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func readState(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open anisette state: %w", err)
	}
	defer file.Close()
	state, err := io.ReadAll(io.LimitReader(file, maxStateSize+1))
	if err != nil {
		return nil, fmt.Errorf("read anisette state: %w", err)
	}
	if len(state) > maxStateSize {
		return nil, errors.New("anisette state exceeds size limit")
	}
	return state, nil
}

func writeState(path string, state []byte) error {
	if len(state) == 0 || len(state) > maxStateSize {
		return errors.New("generated anisette state has an invalid size")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".anisette-v4-*.tmp")
	if err != nil {
		return fmt.Errorf("create anisette state file: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(state)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write anisette state: %w", err)
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace anisette state: %w", err)
	}
	return nil
}
