package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"google.golang.org/protobuf/proto"
)

func geoSourceTestHome(t *testing.T) string {
	t.Helper()
	previousHome, previousFetch := C.Path.HomeDir(), fetchGeoSource
	oldURLs := map[string]string{"GEOSITE": geodata.GeoSiteUrl(), "GEOIP": geodata.GeoIpUrl(), "MMDB": geodata.MmdbUrl(), "ASN": geodata.ASNUrl()}
	home := t.TempDir()
	C.SetHomeDir(home)
	geodata.ClearGeoSiteCache()
	t.Cleanup(func() {
		C.SetHomeDir(previousHome)
		fetchGeoSource = previousFetch
		for kind, link := range oldURLs {
			geoResources[kind].setUrl(link)
		}
		geodata.ClearGeoSiteCache()
	})
	return home
}

func geoSourceTestSite(t *testing.T, names ...string) []byte {
	t.Helper()
	entries := []*router.GeoSite{}
	for _, name := range names {
		entries = append(entries, &router.GeoSite{CountryCode: name, Domain: []*router.Domain{{Type: router.Domain_Domain, Value: name + ".test"}}})
	}
	data, err := proto.Marshal(&router.GeoSiteList{Entry: entries})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func geoSourceTestConfig() *config.RawConfig {
	raw := config.DefaultRawConfig()
	raw.Rule = []string{"GEOSITE,apple-music,DIRECT", "MATCH,DIRECT"}
	raw.GeoXUrl.GeoSite = "https://mirror.test/site.dat"
	return raw
}

func TestGeoSourceReplacesUnknownCacheAndRecordsSource(t *testing.T) {
	home := geoSourceTestHome(t)
	old := geoSourceTestSite(t, "cn")
	path := C.Path.GeoSite()
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	updated := geoSourceTestSite(t, "cn", "apple-music")
	calls := 0
	fetchGeoSource = func(link string) ([]byte, error) { calls++; return updated, nil }
	raw := geoSourceTestConfig()
	if _, err := parseConfigWithGeoSources(raw); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("download calls = %d", calls)
	}
	if _, err := os.Stat(filepath.Join(home, "geo-sources.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfigWithGeoSources(raw); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("unchanged source redownloaded: %d", calls)
	}
	raw.GeoXUrl.GeoSite = "https://another.test/site.dat"
	if _, err := parseConfigWithGeoSources(raw); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("changed source was not downloaded: %d", calls)
	}
}

func TestGeoSourceMissingCategoryRestoresPreviousDatabase(t *testing.T) {
	geoSourceTestHome(t)
	original := geoSourceTestSite(t, "cn", "apple-music")
	path := C.Path.GeoSite()
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	fetchGeoSource = func(string) ([]byte, error) { return geoSourceTestSite(t, "cn"), nil }
	_, err := parseConfigWithGeoSources(geoSourceTestConfig())
	var methodError *MethodError
	if !errors.As(err, &methodError) || methodError.Code != "geo_source_failed" {
		t.Fatalf("error = %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("previous database was not restored")
	}
	if _, err := os.Stat(filepath.Join(C.Path.HomeDir(), "geo-sources.json")); !os.IsNotExist(err) {
		t.Fatal("failed source was recorded")
	}
}

func TestGeoSourceDownloadAndFormatErrorsPreserveExistingFiles(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "download", true: "format"}[broken], func(t *testing.T) {
			geoSourceTestHome(t)
			original := geoSourceTestSite(t, "cn", "apple-music")
			path := C.Path.GeoSite()
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			fetchGeoSource = func(string) ([]byte, error) {
				if broken {
					return []byte("<html>error</html>"), nil
				}
				return nil, errors.New("offline")
			}
			if _, err := parseConfigWithGeoSources(geoSourceTestConfig()); err == nil {
				t.Fatal("broken source was accepted")
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, original) {
				t.Fatal("previous database changed")
			}
		})
	}
}

func TestGeoSourceStagesEveryRequiredFileBeforeInstalling(t *testing.T) {
	geoSourceTestHome(t)
	original := geoSourceTestSite(t, "cn", "apple-music")
	path := C.Path.GeoSite()
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	raw := geoSourceTestConfig()
	raw.GeodataMode = true
	raw.Rule = append(raw.Rule, "GEOIP,CN,DIRECT")
	fetchGeoSource = func(link string) ([]byte, error) {
		if link == raw.GeoXUrl.GeoSite {
			return geoSourceTestSite(t, "cn", "apple-music"), nil
		}
		return nil, errors.New("second resource unavailable")
	}
	if _, err := parseConfigWithGeoSources(raw); err == nil {
		t.Fatal("partial download was accepted")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("first file changed before the second file was ready")
	}
}

func TestGeoSourceDownloadsAreConcurrentBeforeAnyInstallation(t *testing.T) {
	geoSourceTestHome(t)
	raw := geoSourceTestConfig()
	raw.GeodataMode = true
	raw.Rule = append(raw.Rule, "GEOIP,CN,DIRECT")
	started := make(chan string, 2)
	release := make(chan struct{})
	fetchGeoSource = func(link string) ([]byte, error) { started <- link; <-release; return nil, errors.New("offline") }
	done := make(chan error, 1)
	go func() { _, err := parseConfigWithGeoSources(raw); done <- err }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	defer func() { close(release); <-done }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-timer.C:
			t.Fatal("database downloads ran serially")
		}
	}
	select {
	case <-done:
		t.Fatal("configuration completed before its downloads")
	default:
	}
}
