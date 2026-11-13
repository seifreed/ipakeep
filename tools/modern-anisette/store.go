package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"howett.net/plist"
)

const (
	maxStoreInputSize   = 64 * 1024
	maxMetadataSize     = 4 << 20
	errorCodeExpired    = "passwordTokenExpired"
	errorCodeNoLicense  = "licenseRequired"
	stagedPackageName   = "package.ipa"
	stagingDirectory    = "downloads"
	itunesMetadataEntry = "iTunesMetadata.plist"
)

type storeRequest struct {
	Account           appstore.Account `json:"account"`
	AppID             int64            `json:"appId"`
	ExternalVersionID string           `json:"externalVersionId"`
	Limit             int              `json:"limit"`
}

type storeError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

type storeSinf struct {
	ID   int64  `json:"id"`
	Data []byte `json:"sinf"`
}

// stagedItem mirrors the shape of an Apple songList item so the caller can
// parse it like a direct download response; URL is the staged package path.
type stagedItem struct {
	URL      string         `json:"URL"`
	Sinfs    []storeSinf    `json:"sinfs"`
	Metadata map[string]any `json:"metadata"`
}

type storeResponse struct {
	Error                   *storeError    `json:"error,omitempty"`
	ExternalVersionIDs      []string       `json:"externalVersionIds,omitempty"`
	LatestExternalVersionID string         `json:"latestExternalVersionId,omitempty"`
	LatestVersion           string         `json:"latestVersion,omitempty"`
	Item                    *stagedItem    `json:"item,omitempty"`
	Apps                    []appstore.App `json:"apps,omitempty"`
	TotalCount              int            `json:"totalCount,omitempty"`
}

type storeOperation func(appstore.AppStore, storeRequest, string) (storeResponse, error)

var storeOperations = map[string]storeOperation{
	"purchase":      purchase,
	"list-versions": listVersions,
	"download":      download,
	"owned-apps":    ownedApps,
}

// runStore performs an App Store commerce request through upstream ipatool so
// it carries the Store AMD proof, kbsync and session cookies Apple requires.
// Apple-side failures are reported in the JSON response, not the exit status.
func runStore(operation, statePath string, input io.Reader, output io.Writer) error {
	handler, ok := storeOperations[operation]
	if !ok {
		return fmt.Errorf("unknown Store operation %q", operation)
	}
	var request storeRequest
	if err := json.NewDecoder(io.LimitReader(input, maxStoreInputSize)).Decode(&request); err != nil {
		return fmt.Errorf("read Store request: %w", err)
	}
	if request.Account.PasswordToken == "" || request.Account.DirectoryServicesID == "" {
		return errors.New("Store request requires a signed-in account")
	}

	store, jar, err := openStore(statePath)
	if err != nil {
		return err
	}
	response, err := handler(store, request, filepath.Join(filepath.Dir(statePath), stagingDirectory))
	if saveErr := jar.Save(); saveErr != nil && err == nil {
		err = fmt.Errorf("save Store cookie jar: %w", saveErr)
	}
	if err != nil {
		response = storeResponse{Error: classifyStoreError(err)}
	}
	return json.NewEncoder(output).Encode(response)
}

func classifyStoreError(err error) *storeError {
	failure := &storeError{Message: err.Error()}
	switch {
	case errors.Is(err, appstore.ErrPasswordTokenExpired):
		failure.Code = errorCodeExpired
	case errors.Is(err, appstore.ErrLicenseRequired):
		failure.Code = errorCodeNoLicense
	}
	return failure
}

// purchase acquires a free license. Apple answers every buyProduct request
// whose token is not freshly authenticated with "Sign In" (2034), even for apps
// the account already owns, so an expired answer is only reported when the
// account really lacks the license.
func purchase(store appstore.AppStore, request storeRequest, _ string) (storeResponse, error) {
	if request.AppID <= 0 {
		return storeResponse{}, errors.New("Store request requires an app id")
	}
	app := appstore.App{ID: request.AppID}
	err := store.Purchase(appstore.PurchaseInput{Account: request.Account, App: app})
	if errors.Is(err, appstore.ErrPasswordTokenExpired) {
		_, ownedErr := store.ListVersions(appstore.ListVersionsInput{Account: request.Account, App: app})
		if ownedErr == nil {
			return storeResponse{}, nil
		}
		return storeResponse{}, fmt.Errorf("Apple requires a recent sign-in to acquire this license: %w", err)
	}
	if errors.Is(err, appstore.ErrLicenseAlreadyExists) {
		err = nil
	}
	return storeResponse{}, err
}

func listVersions(store appstore.AppStore, request storeRequest, _ string) (storeResponse, error) {
	if request.AppID <= 0 {
		return storeResponse{}, errors.New("Store request requires an app id")
	}
	app := appstore.App{ID: request.AppID}
	versions, err := store.ListVersions(appstore.ListVersionsInput{Account: request.Account, App: app})
	if err != nil {
		return storeResponse{}, err
	}
	response := storeResponse{
		ExternalVersionIDs:      versions.ExternalVersionIdentifiers,
		LatestExternalVersionID: versions.LatestExternalVersionID,
	}
	// The catalog version labels the listing only; it must not fail without it.
	lookup, err := store.Lookup(appstore.LookupInput{Account: request.Account, AppID: request.AppID})
	if err == nil {
		response.LatestVersion = lookup.App.Version
	}
	return response, nil
}

// ownedApps lists the apps the account already owns. Upstream fetches the full
// purchase history across storefronts, then returns the first page capped at
// the requested limit, most recent purchase first.
func ownedApps(store appstore.AppStore, request storeRequest, _ string) (storeResponse, error) {
	limit := request.Limit
	if limit <= 0 {
		limit = appstore.DefaultOwnedAppsLimit
	}
	if limit > appstore.MaxOwnedAppsLimit {
		limit = appstore.MaxOwnedAppsLimit
	}
	output, err := store.OwnedApps(appstore.OwnedAppsInput{
		Account: request.Account,
		Page:    1,
		Limit:   limit,
	})
	if err != nil {
		return storeResponse{}, err
	}
	return storeResponse{Apps: output.Results, TotalCount: output.TotalCount}, nil
}

func download(store appstore.AppStore, request storeRequest, staging string) (storeResponse, error) {
	if request.AppID <= 0 {
		return storeResponse{}, errors.New("Store request requires an app id")
	}
	if err := ensurePrivateDirectory(staging); err != nil {
		return storeResponse{}, err
	}
	directory, err := os.MkdirTemp(staging, "download-*")
	if err != nil {
		return storeResponse{}, fmt.Errorf("create download staging directory: %w", err)
	}
	item, err := stagePackage(store, request, filepath.Join(directory, stagedPackageName))
	if err != nil {
		_ = os.RemoveAll(directory)
		return storeResponse{}, err
	}
	return storeResponse{Item: item}, nil
}

func stagePackage(store appstore.AppStore, request storeRequest, path string) (*stagedItem, error) {
	result, err := store.Download(appstore.DownloadInput{
		Account:           request.Account,
		App:               appstore.App{ID: request.AppID},
		OutputPath:        path,
		ExternalVersionID: request.ExternalVersionID,
	})
	if err != nil {
		return nil, err
	}
	metadata, err := readITunesMetadata(result.DestinationPath)
	if err != nil {
		return nil, err
	}
	sinfs := make([]storeSinf, 0, len(result.Sinfs))
	for _, sinf := range result.Sinfs {
		sinfs = append(sinfs, storeSinf{ID: sinf.ID, Data: sinf.Data})
	}
	return &stagedItem{URL: result.DestinationPath, Sinfs: sinfs, Metadata: metadata}, nil
}

// readITunesMetadata returns the metadata upstream wrote into the package so
// the caller can name and re-patch it exactly like a direct download.
func readITunesMetadata(path string) (map[string]any, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open downloaded package: %w", err)
	}
	defer reader.Close()
	file, err := reader.Open(itunesMetadataEntry)
	if err != nil {
		return nil, fmt.Errorf("find package metadata: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("read package metadata: %w", err)
	}
	if len(data) > maxMetadataSize {
		return nil, errors.New("package metadata exceeds size limit")
	}
	var metadata map[string]any
	if _, err = plist.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("decode package metadata: %w", err)
	}
	return metadata, nil
}
