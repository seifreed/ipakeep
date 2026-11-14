package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/majd/ipatool/v2/pkg/appstore"
)

func TestClassifyStoreErrorKeepsUpstreamSentinels(t *testing.T) {
	expired := classifyStoreError(fmt.Errorf("purchase: %w", appstore.ErrPasswordTokenExpired))
	if expired.Code != errorCodeExpired {
		t.Fatalf("expired code = %q", expired.Code)
	}
	if code := classifyStoreError(appstore.ErrLicenseRequired).Code; code != errorCodeNoLicense {
		t.Fatalf("license code = %q", code)
	}
	if code := classifyStoreError(errors.New("other")).Code; code != "" {
		t.Fatalf("generic code = %q", code)
	}
}

func TestReadITunesMetadataDecodesThePackagePlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create(itunesMetadataEntry)
	if err == nil {
		_, err = entry.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>softwareVersionBundleId</key><string>com.example</string></dict></plist>`))
	}
	if err == nil {
		err = writer.Close()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := readITunesMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata["softwareVersionBundleId"] != "com.example" {
		t.Fatalf("metadata = %v", metadata)
	}
}

func TestRunStoreRejectsUnknownInvalidAndUnsignedRequests(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation string
		request   string
	}{
		{name: "unknown operation", operation: "unknown", request: "{}"},
		{name: "invalid JSON", operation: "purchase", request: "{\"account\":"},
		{name: "unsigned account", operation: "purchase", request: "{\"account\":{}}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := runStore(test.operation, filepath.Join(t.TempDir(), "state.json"), strings.NewReader(test.request), &output)
			if err == nil {
				t.Fatal("runStore accepted an invalid request")
			}
		})
	}
}

func TestRunStoreReturnsPurchaseValidationErrorAsJSON(t *testing.T) {
	request := "{\"account\":{\"passwordToken\":\"token\",\"directoryServicesIdentifier\":\"dsid\"}}"
	var output bytes.Buffer
	if err := runStore("purchase", filepath.Join(t.TempDir(), "state.json"), strings.NewReader(request), &output); err != nil {
		t.Fatal(err)
	}
	var response storeResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Message != "Store request requires an app id" {
		t.Fatalf("response = %+v", response)
	}
}

func TestStoreOperationsValidateAppIDsBeforeCallingStore(t *testing.T) {
	for name, operation := range map[string]storeOperation{
		"purchase":      purchase,
		"list versions": listVersions,
		"download":      download,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := operation(nil, storeRequest{}, t.TempDir()); err == nil || err.Error() != "Store request requires an app id" {
				t.Fatalf("operation error = %v", err)
			}
		})
	}
}

func TestReadITunesMetadataRejectsInvalidPackages(t *testing.T) {
	if _, err := readITunesMetadata(filepath.Join(t.TempDir(), "missing.ipa")); err == nil {
		t.Fatal("readITunesMetadata accepted a missing package")
	}
	path := filepath.Join(t.TempDir(), "empty.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	if _, err = writer.Create("Payload/app"); err == nil {
		err = writer.Close()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readITunesMetadata(path); err == nil {
		t.Fatal("readITunesMetadata accepted a package without metadata")
	}
}

func TestReadITunesMetadataRejectsMalformedAndOversizedMetadata(t *testing.T) {
	for name, metadata := range map[string][]byte{
		"malformed": []byte("not a plist"),
		"oversized": bytes.Repeat([]byte("x"), maxMetadataSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metadata.ipa")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			entry, err := writer.Create(itunesMetadataEntry)
			if err == nil {
				_, err = entry.Write(metadata)
			}
			if err == nil {
				err = writer.Close()
			}
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readITunesMetadata(path); err == nil {
				t.Fatal("readITunesMetadata accepted invalid metadata")
			}
		})
	}
}

type storeStub struct {
	login       appstore.LoginOutput
	loginErr    error
	purchaseErr error
	versions    appstore.ListVersionsOutput
	versionsErr error
	lookup      appstore.LookupOutput
	lookupErr   error
	owned       appstore.OwnedAppsOutput
	ownedErr    error
	ownedInput  appstore.OwnedAppsInput
	download    func(appstore.DownloadInput) (appstore.DownloadOutput, error)
}

func (s *storeStub) Login(appstore.LoginInput) (appstore.LoginOutput, error) {
	return s.login, s.loginErr
}
func (s *storeStub) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{}, nil
}
func (s *storeStub) Revoke() error { return nil }
func (s *storeStub) Lookup(appstore.LookupInput) (appstore.LookupOutput, error) {
	return s.lookup, s.lookupErr
}
func (s *storeStub) Search(appstore.SearchInput) (appstore.SearchOutput, error) {
	return appstore.SearchOutput{}, nil
}
func (s *storeStub) OwnedApps(input appstore.OwnedAppsInput) (appstore.OwnedAppsOutput, error) {
	s.ownedInput = input
	return s.owned, s.ownedErr
}
func (s *storeStub) Purchase(appstore.PurchaseInput) error { return s.purchaseErr }
func (s *storeStub) Download(input appstore.DownloadInput) (appstore.DownloadOutput, error) {
	if s.download == nil {
		return appstore.DownloadOutput{}, nil
	}
	return s.download(input)
}
func (s *storeStub) ReplicateSinf(appstore.ReplicateSinfInput) error { return nil }
func (s *storeStub) ListVersions(appstore.ListVersionsInput) (appstore.ListVersionsOutput, error) {
	return s.versions, s.versionsErr
}
func (s *storeStub) GetVersionMetadata(appstore.GetVersionMetadataInput) (appstore.GetVersionMetadataOutput, error) {
	return appstore.GetVersionMetadataOutput{}, nil
}
func (s *storeStub) Bag(appstore.BagInput) (appstore.BagOutput, error) {
	return appstore.BagOutput{}, nil
}

func TestPurchaseHandlesExistingAndExpiredLicenses(t *testing.T) {
	request := storeRequest{AppID: 9}
	if _, err := purchase(&storeStub{}, request, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := purchase(&storeStub{purchaseErr: appstore.ErrLicenseAlreadyExists}, request, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := purchase(&storeStub{purchaseErr: appstore.ErrPasswordTokenExpired, versionsErr: errors.New("not owned")}, request, ""); err == nil {
		t.Fatal("purchase hid an expired token for an unowned app")
	}
	if _, err := purchase(&storeStub{purchaseErr: appstore.ErrPasswordTokenExpired}, request, ""); err != nil {
		t.Fatalf("purchase rejected an already-owned app: %v", err)
	}
}

func TestListVersionsReturnsVersionsAndOptionalCatalogLabel(t *testing.T) {
	store := &storeStub{
		versions: appstore.ListVersionsOutput{ExternalVersionIdentifiers: []string{"v2", "v1"}, LatestExternalVersionID: "v2"},
		lookup:   appstore.LookupOutput{App: appstore.App{Version: "2.0"}},
	}
	response, err := listVersions(store, storeRequest{AppID: 7}, "")
	if err != nil {
		t.Fatal(err)
	}
	if response.LatestVersion != "2.0" || response.LatestExternalVersionID != "v2" || len(response.ExternalVersionIDs) != 2 {
		t.Fatalf("listVersions response = %+v", response)
	}
	store.lookupErr = errors.New("catalog unavailable")
	response, err = listVersions(store, storeRequest{AppID: 7}, "")
	if err != nil || response.LatestVersion != "" {
		t.Fatalf("optional lookup response = %+v, %v", response, err)
	}
	store.versionsErr = errors.New("history unavailable")
	if _, err = listVersions(store, storeRequest{AppID: 7}, ""); err == nil {
		t.Fatal("listVersions hid a history error")
	}
}

func TestOwnedAppsAppliesDefaultAndMaximumLimits(t *testing.T) {
	store := &storeStub{owned: appstore.OwnedAppsOutput{Results: []appstore.App{{ID: 4}}, TotalCount: 8}}
	response, err := ownedApps(store, storeRequest{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if store.ownedInput.Limit != appstore.DefaultOwnedAppsLimit || store.ownedInput.Page != 1 || response.TotalCount != 8 {
		t.Fatalf("default owned apps = %+v, %+v", store.ownedInput, response)
	}
	_, err = ownedApps(store, storeRequest{Limit: appstore.MaxOwnedAppsLimit + 1}, "")
	if err != nil || store.ownedInput.Limit != appstore.MaxOwnedAppsLimit {
		t.Fatalf("maximum owned apps limit = %d, %v", store.ownedInput.Limit, err)
	}
	store.ownedErr = errors.New("purchase history unavailable")
	if _, err = ownedApps(store, storeRequest{}, ""); err == nil {
		t.Fatal("ownedApps hid a repository error")
	}
}

func TestDownloadStagesPackageAndReturnsMetadata(t *testing.T) {
	store := &storeStub{download: func(input appstore.DownloadInput) (appstore.DownloadOutput, error) {
		file, err := os.Create(input.OutputPath)
		if err != nil {
			return appstore.DownloadOutput{}, err
		}
		writer := zip.NewWriter(file)
		entry, err := writer.Create(itunesMetadataEntry)
		if err == nil {
			_, err = entry.Write([]byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>name</key><string>Demo</string></dict></plist>"))
		}
		if err == nil {
			err = writer.Close()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return appstore.DownloadOutput{}, err
		}
		return appstore.DownloadOutput{DestinationPath: input.OutputPath, Sinfs: []appstore.Sinf{{ID: 12, Data: []byte("sinf")}}}, nil
	}}
	response, err := download(store, storeRequest{AppID: 42, ExternalVersionID: "version"}, filepath.Join(t.TempDir(), stagingDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if response.Item == nil || response.Item.Metadata["name"] != "Demo" || len(response.Item.Sinfs) != 1 || response.Item.Sinfs[0].ID != 12 {
		t.Fatalf("download response = %+v", response)
	}
}

func TestDownloadPropagatesStoreAndMetadataErrors(t *testing.T) {
	staging := filepath.Join(t.TempDir(), stagingDirectory)
	store := &storeStub{download: func(appstore.DownloadInput) (appstore.DownloadOutput, error) {
		return appstore.DownloadOutput{}, errors.New("download failed")
	}}
	if _, err := download(store, storeRequest{AppID: 42}, staging); err == nil || err.Error() != "download failed" {
		t.Fatalf("download error = %v", err)
	}
	store.download = func(appstore.DownloadInput) (appstore.DownloadOutput, error) {
		return appstore.DownloadOutput{DestinationPath: filepath.Join(t.TempDir(), "missing.ipa")}, nil
	}
	if _, err := download(store, storeRequest{AppID: 42}, staging); err == nil {
		t.Fatal("download accepted missing package metadata")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := download(store, storeRequest{AppID: 42}, blocked); err == nil {
		t.Fatal("download accepted a file as staging directory")
	}
}
