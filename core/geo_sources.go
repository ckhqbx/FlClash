package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

var geoSourceMu sync.RWMutex

var fetchGeoSource = func(link string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	response, err := mihomoHttp.HttpRequest(ctx, link, http.MethodGet, nil, nil)
	if err != nil {
		return nil, errors.New("download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 128<<20+1))
	if err != nil {
		return nil, errors.New("download interrupted")
	}
	if len(data) == 0 || len(data) > 128<<20 {
		return nil, errors.New("invalid database size")
	}
	return data, nil
}

type geoSourceFile struct {
	kind, path, link, digest, stage, backup string
	existed                                 bool
}

func geoSourceDigest(link string) string {
	sum := sha256.Sum256([]byte(link))
	return hex.EncodeToString(sum[:])
}

func requiredGeoSources(raw *config.RawConfig) []geoSourceFile {
	data, _ := json.Marshal([]any{raw.Rule, raw.SubRules, raw.DNS, raw.Sniffer, raw.RuleProvider})
	text := strings.ToLower(string(data))
	files := []geoSourceFile{}
	if strings.Contains(text, "geosite,") || strings.Contains(text, "geosite:") {
		files = append(files, geoSourceFile{kind: "GEOSITE", path: C.Path.GeoSite(), link: raw.GeoXUrl.GeoSite})
	}
	if strings.Contains(text, "geoip,") || strings.Contains(text, "geoip:") || (len(raw.DNS.Fallback) > 0 && raw.DNS.FallbackFilter.GeoIP) {
		if raw.GeodataMode {
			files = append(files, geoSourceFile{kind: "GEOIP", path: C.Path.GeoIP(), link: raw.GeoXUrl.GeoIp})
		} else {
			files = append(files, geoSourceFile{kind: "MMDB", path: C.Path.MMDB(), link: raw.GeoXUrl.Mmdb})
		}
	}
	if strings.Contains(text, "ip-asn,") {
		files = append(files, geoSourceFile{kind: "ASN", path: C.Path.ASN(), link: raw.GeoXUrl.ASN})
	}
	return files
}

func validateGeoSource(kind string, data []byte) error {
	if kind == "MMDB" || kind == "ASN" {
		reader, err := maxminddb.FromBytes(data)
		if err != nil {
			return errors.New("invalid MMDB database")
		}
		return reader.Close()
	}
	if kind == "GEOSITE" {
		list := new(router.GeoSiteList)
		if err := proto.Unmarshal(data, list); err != nil || len(list.Entry) == 0 {
			return errors.New("invalid GeoSite database")
		}
	} else {
		list := new(router.GeoIPList)
		if err := proto.Unmarshal(data, list); err != nil || len(list.Entry) == 0 {
			return errors.New("invalid GeoIP database")
		}
	}
	return nil
}

func writeGeoSource(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".geo-source-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func resetGeoSource(kind string) {
	switch kind {
	case "GEOSITE":
		geodata.ClearGeoSiteCache()
	case "GEOIP":
		geodata.ClearGeoIPCache()
	case "MMDB":
		mmdb.ReloadIP()
	case "ASN":
		mmdb.ReloadASN()
	}
}

func parseConfigWithGeoSources(raw *config.RawConfig) (*config.Config, error) {
	files := requiredGeoSources(raw)
	if len(files) == 0 {
		return config.ParseRawConfig(raw)
	}
	geoSourceMu.Lock()
	defer geoSourceMu.Unlock()
	manifestPath := filepath.Join(C.Path.HomeDir(), "geo-sources.json")
	manifest := map[string]string{}
	if data, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(data, &manifest)
	}
	if manifest == nil {
		manifest = map[string]string{}
	}
	changed := []geoSourceFile{}
	stageDir, err := os.MkdirTemp(C.Path.HomeDir(), ".geo-sources-")
	if err != nil {
		return nil, &MethodError{Code: "geo_source_failed", Message: "Cannot stage Geo databases"}
	}
	defer os.RemoveAll(stageDir)
	for _, file := range files {
		file.digest = geoSourceDigest(file.link)
		_, statErr := os.Stat(file.path)
		if manifest[file.kind] == file.digest && statErr == nil {
			continue
		}
		data, downloadErr := fetchGeoSource(file.link)
		if downloadErr == nil {
			downloadErr = validateGeoSource(file.kind, data)
		}
		if downloadErr != nil {
			return nil, &MethodError{Code: "geo_source_failed", Message: fmt.Sprintf("%s: %v; previous databases preserved", file.kind, downloadErr)}
		}
		file.stage = filepath.Join(stageDir, file.kind+".new")
		file.backup = filepath.Join(stageDir, file.kind+".old")
		if err := os.WriteFile(file.stage, data, 0600); err != nil {
			return nil, err
		}
		changed = append(changed, file)
	}
	oldURLs := map[string]string{"GEOSITE": geodata.GeoSiteUrl(), "GEOIP": geodata.GeoIpUrl(), "MMDB": geodata.MmdbUrl(), "ASN": geodata.ASNUrl()}
	oldMode, oldLoader := geodata.GeodataMode(), geodata.LoaderName()
	installed := []geoSourceFile{}
	rollback := func() {
		for kind, link := range oldURLs {
			geoResources[kind].setUrl(link)
		}
		geodata.SetGeodataMode(oldMode)
		geodata.SetLoader(oldLoader)
		for i := len(installed) - 1; i >= 0; i-- {
			file := installed[i]
			if file.existed {
				_ = os.Rename(file.backup, file.path)
			} else {
				_ = os.Remove(file.path)
			}
			resetGeoSource(file.kind)
		}
	}
	for _, file := range changed {
		if _, err := os.Stat(file.path); err == nil {
			if err := os.Link(file.path, file.backup); err != nil {
				rollback()
				return nil, err
			}
			file.existed = true
		} else if !os.IsNotExist(err) {
			rollback()
			return nil, err
		}
		if err := os.Rename(file.stage, file.path); err != nil {
			rollback()
			return nil, err
		}
		installed = append(installed, file)
		resetGeoSource(file.kind)
	}
	cfg, err := config.ParseRawConfig(raw)
	if err != nil {
		rollback()
		if len(changed) > 0 {
			return nil, &MethodError{Code: "geo_source_failed", Message: "Geo source configuration rejected; previous databases restored: " + err.Error()}
		}
		return nil, err
	}
	for _, file := range changed {
		manifest[file.kind] = file.digest
	}
	if len(changed) > 0 {
		data, _ := json.Marshal(manifest)
		if err = writeGeoSource(manifestPath, data); err != nil {
			rollback()
			return nil, err
		}
	}
	return cfg, nil
}
