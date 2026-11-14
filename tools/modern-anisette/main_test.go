package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/pkg/appstore"
)

func TestReadStateReturnsNilWhenMissingAndRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	state, err := readState(path)
	if err != nil || state != nil {
		t.Fatalf("readState(missing) = %q, %v", state, err)
	}
	if err := os.WriteFile(path, make([]byte, maxStateSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("readState accepted an oversized state")
	}
}

func TestWriteStateRejectsInvalidSizesAndMissingDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := writeState(filepath.Join(directory, "empty"), nil); err == nil {
		t.Fatal("writeState accepted empty state")
	}
	if err := writeState(filepath.Join(directory, "large"), make([]byte, maxStateSize+1)); err == nil {
		t.Fatal("writeState accepted oversized state")
	}
	if err := writeState(filepath.Join(directory, "missing", "state"), []byte("state")); err == nil {
		t.Fatal("writeState accepted a missing parent directory")
	}
}

func TestEnsurePrivateDirectorySecuresAndRejectsFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions = %o, want 700", info.Mode().Perm())
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(file); err == nil {
		t.Fatal("ensurePrivateDirectory accepted a file")
	}
}

func TestFlattenHeadersAcceptsEmptyAndSingleValueHeaders(t *testing.T) {
	if headers, err := flattenHeaders(nil); err != nil || len(headers) != 0 {
		t.Fatalf("flattenHeaders(nil) = %v, %v", headers, err)
	}
	headers, err := flattenHeaders(http.Header{"X-Apple-I-Md": {"value"}})
	if err != nil || headers["X-Apple-I-Md"] != "value" {
		t.Fatalf("flattenHeaders(single) = %v, %v", headers, err)
	}
	if _, err = flattenHeaders(http.Header{"X-Apple-I-Md": {""}}); err == nil {
		t.Fatal("flattenHeaders accepted an empty header value")
	}
}

func TestLockStateCreatesPrivateLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lock")
	file, err := lockState(path)
	if err != nil {
		t.Fatal(err)
	}
	unlockState(file)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestStateKeychainSeparatesPersistentStateAndTemporaryValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	keychain := &stateKeychain{statePath: path, values: map[string][]byte{}}
	if _, err := keychain.Get(anisetteKeychainKey); err == nil {
		t.Fatal("Get accepted missing anisette state")
	}
	if err := keychain.Set(anisetteKeychainKey, []byte("anisette")); err != nil {
		t.Fatal(err)
	}
	if value, err := keychain.Get(anisetteKeychainKey); err != nil || string(value) != "anisette" {
		t.Fatalf("anisette Get = %q, %v", value, err)
	}
	if err := keychain.Set("temporary", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if value, err := keychain.Get("temporary"); err != nil || string(value) != "value" {
		t.Fatalf("temporary Get = %q, %v", value, err)
	}
	if err := keychain.Remove("temporary"); err != nil {
		t.Fatal(err)
	}
	if _, err := keychain.Get("temporary"); err == nil {
		t.Fatal("Get returned a removed key")
	}
	if err := keychain.Remove(anisetteKeychainKey); err != nil {
		t.Fatal(err)
	}
	if value, err := keychain.Get(anisetteKeychainKey); err != nil || string(value) != "anisette" {
		t.Fatalf("persistent state changed after Remove: %q, %v", value, err)
	}
}

func TestRunDispatchesLoginAndStoreCommandsWithoutAppleRequests(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	originalArgs := os.Args
	originalStdin := os.Stdin
	defer func() {
		os.Args = originalArgs
		os.Stdin = originalStdin
	}()

	input, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("{"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = input
	os.Args = []string{"ipakeep", "login"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "read login request") {
		t.Fatalf("login dispatch error = %v", err)
	}

	os.Args = []string{"ipakeep", "unknown"}
	if err := run(); err == nil || !strings.Contains(err.Error(), "unknown Store operation") {
		t.Fatalf("Store dispatch error = %v", err)
	}
}

func TestReadStateRejectsDirectoryAndLockRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	if _, err := readState(directory); err == nil {
		t.Fatal("readState accepted a directory")
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "state.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := lockState(link); err == nil {
		t.Fatal("lockState accepted a symlink")
	}
}

func TestRunLoginRejectsInvalidAndIncompleteRequests(t *testing.T) {
	for _, request := range []string{"{", "{\"email\":\"\",\"password\":\"\"}"} {
		if err := runLogin(filepath.Join(t.TempDir(), "state.json"), strings.NewReader(request), io.Discard); err == nil {
			t.Fatalf("runLogin accepted %q", request)
		}
	}
}

func TestRunLoginRejectsCookieJarLoadErrors(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	if err := os.WriteFile(filepath.Join(directory, "store-cookies"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := `{"email":"user@example.com","password":"secret"}`
	err := runLogin(statePath, strings.NewReader(request), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "open Store cookie jar") {
		t.Fatalf("runLogin cookie jar error = %v", err)
	}
}

func TestRunLoginCompletesThroughTheStore(t *testing.T) {
	jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(t.TempDir(), "cookies")})
	if err != nil {
		t.Fatal(err)
	}
	store := &storeStub{login: appstore.LoginOutput{Account: appstore.Account{Email: "user@example.com"}}}
	var output bytes.Buffer
	request := `{"email":"user@example.com","password":"secret","code":"123456"}`
	err = runLoginWithOpener("state.json", strings.NewReader(request), &output, func(path string) (appstore.AppStore, *cookiejar.Jar, error) {
		if path != "state.json" {
			t.Fatalf("state path = %q", path)
		}
		return store, jar, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var response loginResponse
	if err = json.Unmarshal(output.Bytes(), &response); err != nil || response.Account.Email != "user@example.com" {
		t.Fatalf("login response = %+v, %v", response, err)
	}
}

func TestRunDispatchesValidStoreRequestWithoutAppleCalls(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	request, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if _, err = request.WriteString(`{"account":{"passwordToken":"token","directoryServicesIdentifier":"dsid"},"appId":0}`); err != nil {
		t.Fatal(err)
	}
	if _, err = request.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	originalArgs, originalStdin := os.Args, os.Stdin
	defer func() {
		os.Args, os.Stdin = originalArgs, originalStdin
	}()
	os.Args = []string{"ipakeep", "purchase"}
	os.Stdin = request
	if err = run(); err != nil {
		t.Fatalf("run valid Store request = %v", err)
	}
}

func TestMainReportsErrorsAndReturnsOnSuccess(t *testing.T) {
	originalRun, originalExit := runMain, exitMain
	defer func() { runMain, exitMain = originalRun, originalExit }()
	runMain = func() error { return nil }
	exitMain = func(code int) { t.Fatalf("exit called with %d on success", code) }
	main()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	defer func() { os.Stderr = originalStderr }()
	os.Stderr = writer
	var exitCode int
	runMain = func() error { return errors.New("failed") }
	exitMain = func(code int) { exitCode = code }
	main()
	_ = writer.Close()
	output, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || exitCode != 1 || string(output) != "failed\n" {
		t.Fatalf("main error path: code=%d output=%q err=%v", exitCode, output, err)
	}
}

func runDefaultCommand(t *testing.T, config string) (string, error) {
	t.Helper()
	t.Setenv("HOME", config)
	originalArgs, originalStdout := os.Args, os.Stdout
	defer func() { os.Args, os.Stdout = originalArgs, originalStdout }()
	os.Args = []string{"ipakeep"}
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = writer
	runErr := run()
	_ = writer.Close()
	os.Stdout = originalStdout
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		return "", readErr
	}
	return string(output), runErr
}

func TestRunAnisetteGenerationOutcomesWithoutApple(t *testing.T) {
	originalGenerator := generateAnisetteHeaders
	defer func() { generateAnisetteHeaders = originalGenerator }()

	t.Run("writes headers and state", func(t *testing.T) {
		config := t.TempDir()
		generateAnisetteHeaders = func(context.Context, *http.Client, []byte) (http.Header, []byte, error) {
			return http.Header{"X-Test": {"value"}}, []byte("state"), nil
		}
		output, err := runDefaultCommand(t, config)
		if err != nil {
			t.Fatal(err)
		}
		var response response
		if err = json.Unmarshal([]byte(output), &response); err != nil || response.Headers["X-Test"] != "value" {
			t.Fatalf("Anisette response = %+v, %v", response, err)
		}
		statePath := filepath.Join(config, "Library", "Application Support", "ipakeep", "anisette-v4.json")
		state, err := readState(statePath)
		if err != nil || string(state) != "state" {
			t.Fatalf("persisted state = %q, %v", state, err)
		}
	})

	t.Run("generator failure", func(t *testing.T) {
		generateAnisetteHeaders = func(context.Context, *http.Client, []byte) (http.Header, []byte, error) {
			return nil, nil, errors.New("offline")
		}
		_, err := runDefaultCommand(t, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "generate local Apple Anisette") {
			t.Fatalf("generator error = %v", err)
		}
	})

	t.Run("invalid generated state", func(t *testing.T) {
		generateAnisetteHeaders = func(context.Context, *http.Client, []byte) (http.Header, []byte, error) {
			return http.Header{"X-Test": {"value"}}, nil, nil
		}
		_, err := runDefaultCommand(t, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "invalid size") {
			t.Fatalf("state write error = %v", err)
		}
	})

	t.Run("invalid response headers", func(t *testing.T) {
		generateAnisetteHeaders = func(context.Context, *http.Client, []byte) (http.Header, []byte, error) {
			return http.Header{"X-Test": {"one", "two"}}, []byte("state"), nil
		}
		_, err := runDefaultCommand(t, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "invalid X-Test header") {
			t.Fatalf("header error = %v", err)
		}
	})
}

func TestRunRejectsConfigurationAndStatePathErrors(t *testing.T) {
	t.Run("missing config directory", func(t *testing.T) {
		_, err := runDefaultCommand(t, "")
		if err == nil || !strings.Contains(err.Error(), "find user config directory") {
			t.Fatalf("config error = %v", err)
		}
	})

	t.Run("invalid config parent", func(t *testing.T) {
		config := t.TempDir()
		if err := os.WriteFile(filepath.Join(config, "Library"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runDefaultCommand(t, config)
		if err == nil || !strings.Contains(err.Error(), "create anisette state directory") {
			t.Fatalf("directory error = %v", err)
		}
	})

	t.Run("lock symlink", func(t *testing.T) {
		config := t.TempDir()
		stateDir := filepath.Join(config, "Library", "Application Support", "ipakeep")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(stateDir, "anisette-v4.json.lock")
		if err := os.Symlink(target, lockPath); err != nil {
			t.Fatal(err)
		}
		_, err := runDefaultCommand(t, config)
		if err == nil || !strings.Contains(err.Error(), "open anisette state lock") {
			t.Fatalf("lock error = %v", err)
		}
	})

	t.Run("state symlink", func(t *testing.T) {
		config := t.TempDir()
		stateDir := filepath.Join(config, "Library", "Application Support", "ipakeep")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(stateDir, "anisette-v4.json")); err != nil {
			t.Fatal(err)
		}
		called := false
		original := generateAnisetteHeaders
		generateAnisetteHeaders = func(context.Context, *http.Client, []byte) (http.Header, []byte, error) {
			called = true
			return nil, nil, nil
		}
		defer func() { generateAnisetteHeaders = original }()
		_, err := runDefaultCommand(t, config)
		if err == nil || called {
			t.Fatalf("state symlink result: err=%v generator_called=%t", err, called)
		}
	})
}

func TestStateFilesystemOperationsReportInjectedErrors(t *testing.T) {
	t.Run("directory inspection", func(t *testing.T) {
		original := inspectStateDirectory
		inspectStateDirectory = func(string) (os.FileInfo, error) { return nil, errors.New("stat failed") }
		defer func() { inspectStateDirectory = original }()
		err := ensurePrivateDirectory(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "inspect anisette state directory") {
			t.Fatalf("inspect error = %v", err)
		}
	})

	t.Run("directory permissions", func(t *testing.T) {
		original := secureStateDirectory
		secureStateDirectory = func(string, os.FileMode) error { return errors.New("chmod failed") }
		defer func() { secureStateDirectory = original }()
		err := ensurePrivateDirectory(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "secure anisette state directory") {
			t.Fatalf("chmod error = %v", err)
		}
	})

	t.Run("lock permissions", func(t *testing.T) {
		original := secureLockFile
		secureLockFile = func(*os.File, os.FileMode) error { return errors.New("chmod failed") }
		defer func() { secureLockFile = original }()
		_, err := lockState(filepath.Join(t.TempDir(), "state.lock"))
		if err == nil || !strings.Contains(err.Error(), "secure anisette state lock") {
			t.Fatalf("lock chmod error = %v", err)
		}
	})

	t.Run("lock operation", func(t *testing.T) {
		original := lockStateFile
		lockStateFile = func(int, int) error { return errors.New("flock failed") }
		defer func() { lockStateFile = original }()
		_, err := lockState(filepath.Join(t.TempDir(), "state.lock"))
		if err == nil || !strings.Contains(err.Error(), "lock anisette state") {
			t.Fatalf("lock error = %v", err)
		}
	})

	t.Run("write state", func(t *testing.T) {
		original := writeStateContents
		writeStateContents = func(*os.File, []byte) error { return errors.New("write failed") }
		defer func() { writeStateContents = original }()
		err := writeState(filepath.Join(t.TempDir(), "state.json"), []byte("state"))
		if err == nil || !strings.Contains(err.Error(), "write anisette state") {
			t.Fatalf("write error = %v", err)
		}
	})

	t.Run("replace state", func(t *testing.T) {
		original := replaceStateFile
		replaceStateFile = func(string, string) error { return errors.New("rename failed") }
		defer func() { replaceStateFile = original }()
		err := writeState(filepath.Join(t.TempDir(), "state.json"), []byte("state"))
		if err == nil || !strings.Contains(err.Error(), "replace anisette state") {
			t.Fatalf("replace error = %v", err)
		}
	})
}

func TestFinishLoginHandlesChallengeFailureAndSuccess(t *testing.T) {
	t.Run("two-factor challenge", func(t *testing.T) {
		jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(t.TempDir(), "cookies")})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		store := &storeStub{loginErr: appstore.ErrAuthCodeRequired}
		if err = finishLogin(store, jar, loginRequest{Email: "a@b.c", Password: "secret"}, &output); err != nil {
			t.Fatal(err)
		}
		var response loginResponse
		if err = json.Unmarshal(output.Bytes(), &response); err != nil || !response.AuthCodeRequired {
			t.Fatalf("challenge response = %+v, %v", response, err)
		}
	})

	t.Run("login failure", func(t *testing.T) {
		jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(t.TempDir(), "cookies")})
		if err != nil {
			t.Fatal(err)
		}
		err = finishLogin(&storeStub{loginErr: errors.New("rejected")}, jar, loginRequest{}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "App Store login failed") {
			t.Fatalf("login error = %v", err)
		}
	})

	t.Run("successful login removes password", func(t *testing.T) {
		jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(t.TempDir(), "cookies")})
		if err != nil {
			t.Fatal(err)
		}
		appleURL, err := url.Parse("https://apple.com")
		if err != nil {
			t.Fatal(err)
		}
		jar.SetCookies(appleURL, []*http.Cookie{{Name: "session", Value: "cookie"}})
		account := appstore.Account{Email: "a@b.c", Password: "secret"}
		var output bytes.Buffer
		err = finishLogin(&storeStub{login: appstore.LoginOutput{Account: account}}, jar, loginRequest{}, &output)
		if err != nil {
			t.Fatal(err)
		}
		var response loginResponse
		if err = json.Unmarshal(output.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Account.Password != "" || response.Account.Email != account.Email || len(response.Cookies) != 1 {
			t.Fatalf("login response leaked or changed account: %+v", response.Account)
		}
	})

	t.Run("cookie save failure", func(t *testing.T) {
		jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(t.TempDir(), "missing", "cookies")})
		if err != nil {
			t.Fatal(err)
		}
		account := appstore.Account{Email: "a@b.c"}
		err = finishLogin(&storeStub{login: appstore.LoginOutput{Account: account}}, jar, loginRequest{}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "save Store cookie jar") {
			t.Fatalf("cookie save error = %v", err)
		}
	})
}

func TestWriteStateIsPrivateAndReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anisette-v4.json")
	state := []byte(`{"identifier":"test"}`)

	if err := writeState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := readState(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(state) {
		t.Fatalf("state round trip mismatch: got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestFlattenHeadersRejectsMultipleValues(t *testing.T) {
	_, err := flattenHeaders(http.Header{"X-Apple-I-Md": {"first", "second"}})
	if err == nil {
		t.Fatal("flattenHeaders accepted a multi-valued header")
	}
}

func TestReadStateRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "anisette-v4.json")
	if err := os.WriteFile(target, []byte(`{"identifier":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("readState accepted a symlink")
	}
}

func TestEnsurePrivateDirectoryRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(link); err == nil {
		t.Fatal("ensurePrivateDirectory accepted a symlink")
	}
}
