package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
