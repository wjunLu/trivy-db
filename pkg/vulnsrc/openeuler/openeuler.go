package openeuler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const openEulerFormat = "openEuler-%s"

var (
	eulerDir = "openeuler"

	source = types.DataSource{
		ID:   vulnerability.OpenEuler,
		Name: "openEuler CVRF",
		URL:  "https://repo.openeuler.org/security/data/cvrf",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	log.Println("Saving openEuler CVRF")
	var cvrfs []Cvrf
	rootDir := filepath.Join(dir, "vuln-list", eulerDir)
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cvrf Cvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
			return xerrors.Errorf("failed to decode openEuler CVRF JSON: %w %+v", err, cvrf)
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in openEuler CVRF walk: %w", err)
	}

	if err = vs.save(cvrfs); err != nil {
		return xerrors.Errorf("error in openEuler CVRF save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cvrfs []Cvrf) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []Cvrf) error {
	var uniqOSVers = make(map[string]struct{})
	for _, cvrf := range cvrfs {
		affectedPkgs := getAffectedPackages(cvrf.ProductTree)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, pkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: pkg.FixedVersion,
				Arches:       pkg.Arches,
			}
			// Don't put the same data source multiple times.
			if _, ok := uniqOSVers[pkg.OSVer]; !ok {
				uniqOSVers[pkg.OSVer] = struct{}{}
				if err := vs.dbc.PutDataSource(tx, pkg.OSVer, source); err != nil {
					return xerrors.Errorf("failed to put data source: %w", err)
				}
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, cvrf.Tracking.ID, pkg.Name,
				[]string{pkg.OSVer}, advisory); err != nil {
				return xerrors.Errorf("unable to save %s CVRF: %w", pkg.OSVer, err)
			}
		}

		var references []string
		for _, ref := range cvrf.References {
			references = append(references, ref.URL)
		}

		severity := types.SeverityUnknown
		for _, cvuln := range cvrf.Vulnerabilities {
			for _, threat := range cvuln.Threats {
				sev := severityFromThreat(threat.Severity)
				if severity < sev {
					severity = sev
				}
			}
		}

		vuln := types.VulnerabilityDetail{
			References:  references,
			Title:       cvrf.Title,
			Description: getDetail(cvrf.Notes),
			Severity:    severity,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cvrf.Tracking.ID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save openEuler CVRF vulnerability: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cvrf.Tracking.ID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func getAffectedPackages(productTree ProductTree) []Package {
	var pkgs []Package
	var osArches = make(map[string][]string) // OS version => arches
	for _, branch := range productTree.Branches {
		// `src` pkgs are the really affected pkgs.
		if branch.Type != "Package Arch" || branch.Name == "" {
			continue
		}
		for _, production := range branch.Productions {
			osVer := getOSVersion(production.CPE)
			if osVer == "" {
				log.Printf("Unable to parse OS version: %s", production.CPE)
				continue
			}

			// Store possible architectures for OS version.
			// We need this to find affected architectures for src pkg later.
			if branch.Name != "src" {
				if arches, ok := osArches[osVer]; ok {
					osArches[osVer] = append(arches, branch.Name)
				} else {
					osArches[osVer] = []string{branch.Name}
				}
				continue
			}

			// e.g., `ignition-2.14.0-2` or `ignition-2.14.0-2.oe2203sp2.src.rpm`
			pkgName, pkgVersion := parseProduction(production)
			if pkgName == "" || pkgVersion == "" {
				log.Printf("Unable to parse Production: %s", production)
				continue
			}
			pkg := Package{
				Name:         pkgName,
				FixedVersion: pkgVersion,
				OSVer:        osVer,
			}
			pkgs = append(pkgs, pkg)
		}
	}

	// Fill affected architectures
	for i, pkg := range pkgs {
		arches := lo.Uniq(osArches[pkg.OSVer])
		sort.Strings(arches)
		pkgs[i].Arches = arches
	}

	return pkgs
}

func getOSVersion(cpe string) string {
	// e.g. cpe:/a:openEuler:openEuler:22.03-LTS-SP3
	parts := strings.Split(cpe, ":")
	// Wrong CPE format
	if len(parts) < 4 || len(parts) > 5 || parts[2] != "openEuler" {
		return ""
	}

	// There are 2 separators between OS name and version: `:` (default) and `-` (There are several cases).
	// e.g. cpe:/a:openEuler:openEuler:22.03-LTS-SP3 and
	var version string
	if len(parts) == 5 { // e.g. `cpe:/a:openEuler:openEuler:22.03-LTS-SP3` => `22.03-LTS-SP3`
		version = parts[4]
	} else { // e.g. `cpe:/a:openEuler:openEuler-22.03-LTS` => `openEuler-22.03-LTS` => `22.03-LTS`
		if osName, ver, ok := strings.Cut(parts[3], "-"); ok && osName == "openEuler" {
			version = ver
		}
	}

	// There are cases when different `SP<X>` OSes have different fixed versions
	// see https://github.com/aquasecurity/trivy-db/pull/397#discussion_r1680608109
	// So we need to keep the full version (with `LTS` and `SPX` suffixes)
	if len(strings.Split(version, "-")) > 3 || version == "" {
		log.Printf("Invalid openEuler version: %s", version)
		return ""
	}
	return fmt.Sprintf(openEulerFormat, version)
}

func getDetail(notes []DocumentNote) string {
	for _, n := range notes {
		if n.Type == "General" && n.Title == "Description" {
			return n.Text
		}
	}
	return ""
}

func parseProduction(production Production) (string, string) {
	name, version := splitPkgName(production.ProductID)
	if name == "" || version == "" {
		text, _, _ := strings.Cut(production.Text, ".oe")
		name, version = splitPkgName(text)
	}
	return name, version
}

func splitPkgName(product string) (string, string) {
	// Trim release
	index := strings.LastIndex(product, "-")
	if index == -1 {
		return "", ""
	}

	release := product[index:]
	nameWithVersion := product[:index]

	// Trim version
	index = strings.LastIndex(nameWithVersion, "-")
	if index == -1 {
		return "", ""
	}
	version := nameWithVersion[index+1:] + release
	name := nameWithVersion[:index]

	return name, version
}

func (vs VulnSrc) Get(version, pkgName, arch string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(openEulerFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get openEuler advisories: %w", err)
	}

	// Filter advisories by arch
	advisories = lo.Filter(advisories, func(adv types.Advisory, _ int) bool {
		return slices.Contains(adv.Arches, arch)
	})

	if len(advisories) == 0 {
		return nil, nil
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "Low":
		return types.SeverityLow
	case "Medium":
		return types.SeverityMedium
	case "High":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
