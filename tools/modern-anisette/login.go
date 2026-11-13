package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

const (
	anisetteKeychainKey = "anisette-v4"
	maxLoginInputSize   = 64 * 1024
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

type loginResponse struct {
	AuthCodeRequired bool             `json:"authCodeRequired,omitempty"`
	Account          appstore.Account `json:"account"`
	Cookies          []string         `json:"cookies,omitempty"`
}

// stateKeychain persists ipatool's anisette state in the same file the header
// mode uses, so Store login and GrandSlam share one machine provisioning.
// Every other key only needs to live for this process.
type stateKeychain struct {
	statePath string
	values    map[string][]byte
}

func (k *stateKeychain) Get(key string) ([]byte, error) {
	if key == anisetteKeychainKey {
		state, err := readState(k.statePath)
		if err == nil && len(state) == 0 {
			return nil, errors.New("anisette state not found")
		}
		return state, err
	}
	value, ok := k.values[key]
	if !ok {
		return nil, fmt.Errorf("%s not found", key)
	}
	return value, nil
}

func (k *stateKeychain) Set(key string, data []byte) error {
	if key == anisetteKeychainKey {
		return writeState(k.statePath, data)
	}
	k.values[key] = data
	return nil
}

func (k *stateKeychain) Remove(key string) error {
	delete(k.values, key)
	return nil
}

func runLogin(statePath string, input io.Reader, output io.Writer) error {
	var request loginRequest
	if err := json.NewDecoder(io.LimitReader(input, maxLoginInputSize)).Decode(&request); err != nil {
		return fmt.Errorf("read login request: %w", err)
	}
	if request.Email == "" || request.Password == "" {
		return errors.New("login request requires email and password")
	}

	// The jar must survive between the code-less attempt that makes Apple push a
	// 2FA code and the follow-up attempt that submits it.
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(filepath.Dir(statePath), "store-cookies"),
	})
	if err != nil {
		return fmt.Errorf("open Store cookie jar: %w", err)
	}
	system := operatingsystem.New()
	store := appstore.NewAppStore(appstore.Args{
		Keychain:        &stateKeychain{statePath: statePath, values: map[string][]byte{}},
		CookieJar:       jar,
		OperatingSystem: system,
		Machine:         machine.New(machine.Args{OS: system}),
	})

	result, err := store.Login(appstore.LoginInput{
		Email:    request.Email,
		Password: request.Password,
		AuthCode: request.Code,
	})
	if saveErr := jar.Save(); saveErr != nil && err == nil {
		err = fmt.Errorf("save Store cookie jar: %w", saveErr)
	}
	if errors.Is(err, appstore.ErrAuthCodeRequired) {
		return json.NewEncoder(output).Encode(loginResponse{AuthCodeRequired: true})
	}
	if err != nil {
		return fmt.Errorf("App Store login failed: %w", err)
	}

	response := loginResponse{Account: result.Account}
	response.Account.Password = ""
	for _, cookie := range jar.AllCookies() {
		response.Cookies = append(response.Cookies, cookie.String())
	}
	return json.NewEncoder(output).Encode(response)
}
