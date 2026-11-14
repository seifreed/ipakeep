package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
		if response.Account.Password != "" || response.Account.Email != account.Email {
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
