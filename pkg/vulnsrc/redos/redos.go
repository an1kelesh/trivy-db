package redos

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/an1kelesh/trivy-db/pkg/db"
	"github.com/an1kelesh/trivy-db/pkg/types"
	"github.com/an1kelesh/trivy-db/pkg/utils"
	ustrings "github.com/an1kelesh/trivy-db/pkg/utils/strings"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/vulnerability"
	version "github.com/knqyf263/go-rpm-version"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

var (
	platform = "RedOS Linux %s"
	redosDir = filepath.Join("oval", "redos")
	source   = types.DataSource{
		ID:   vulnerability.RedOS,
		Name: "Red OS OVAL definitions",
		URL:  "https://redos.red-soft.ru/support/secure/redos.xml",
	}
)

type PutInput struct {
	VulnID     string
	Vuln       types.VulnerabilityDetail
	Advisories map[AffectedPackage]types.Advisory
	OVAL       Definition
}

type DB interface {
	db.Operation
	Put(*bolt.Tx, PutInput) error
	Get(release, pkgName string) ([]types.Advisory, error)
}

type VulnSrc struct {
	DB // Those who want to customize Trivy DB can override put/get methods.
}

type RedOS struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB: &RedOS{Operation: db.Config{}},
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list-redos", redosDir)
	ovals, err := vs.parse(rootDir)
	if err != nil {
		return err
	}
	if err = vs.put(ovals); err != nil {
		return xerrors.Errorf("error in RedOS Linux OVAL save: %w", err)
	}

	return nil
}

func (vs *VulnSrc) parse(rootDir string) ([]Definition, error) {
	var ovals []Definition
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var oval Definition
		if err := json.NewDecoder(r).Decode(&oval); err != nil {
			return xerrors.Errorf("failed to decode RedOS Linux OVAL JSON: %w", err)
		}
		ovals = append(ovals, oval)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in RedOS Linux OVAL walk: %w", err)
	}
	return ovals, nil
}

func (vs *VulnSrc) put(ovals []Definition) error {
	log.Println("Saving RedOS Linux OVAL")

	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, ovals []Definition) error {
	for _, oval := range ovals {

		var vulnIDs []string
		for _, Reference := range oval.Metadata.References {
			vulnIDs = append(vulnIDs, Reference.RefID)
		}
		advisories := map[AffectedPackage]types.Advisory{}
		affectedPkg := walkRedOS(oval.Criteria, "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkg {
			if affectedPkg.Package.Name == "" {
				continue
			}
			platformName := affectedPkg.PlatformName()
			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			advisories[affectedPkg] = types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}
		}

		var references []string
		for _, ref := range oval.Metadata.References {
			references = append(references, ref.RefURL)
		}

		for _, vulnID := range vulnIDs {
			vuln := types.VulnerabilityDetail{
				Description: oval.Metadata.Description,
				References:  referencesFromContains(references, []string{vulnID}),
				Title:       oval.Metadata.Title,
				Severity:    severityFromThreat(oval.Metadata.Advisory.Severity),
			}

			err := vs.Put(tx, PutInput{
				VulnID:     vulnID,
				Vuln:       vuln,
				Advisories: advisories,
				OVAL:       oval,
			})
			if err != nil {
				return xerrors.Errorf("db put error: %w", err)
			}
		}
	}

	return nil
}

func (r *RedOS) Put(tx *bolt.Tx, input PutInput) error {
	if err := r.PutVulnerabilityDetail(tx, input.VulnID, source.ID, input.Vuln); err != nil {
		return xerrors.Errorf("failed to save RedOS Linux OVAL vulnerability: %w", err)
	}

	if err := r.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return xerrors.Errorf("failed to save %s: %w", input.VulnID, err)
	}
	for pkg, advisory := range input.Advisories {
		platformName := pkg.Package.Name
		if err := r.PutAdvisoryDetail(tx, input.VulnID, pkg.Package.Name, []string{platformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save RedOS Linux advisory: %w", err)

		}
	}
	return nil
}

func (r *RedOS) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platform, release)
	advisories, err := r.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get RedOS Linux advisories: %w", err)
	}
	return advisories, nil
}

func walkRedOS(cri Criteria, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	var oval Definition
	for _, c := range cri.Criterions {

		ss := strings.Split(c.Comment, " version is less than ")
		if len(ss) != 2 {
			continue
		}
		osVer := (walkRedOSver(oval.Metadata, ""))
		pkgs = append(pkgs, AffectedPackage{
			OSVer: osVer,
			Package: Package{
				Name:         ss[0],
				FixedVersion: version.NewVersion(ss[1]).String(),
			},
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkRedOS(c, osVer, pkgs)
	}
	return pkgs
}

func walkRedOSver(met Metadata, osVer string) string {
	for _, d := range met.AffectedList {
		if strings.HasPrefix(d.Platforms, "RED OS ") {
			osVer = strings.TrimPrefix(d.Platforms, "RED OS ")
		}
	}
	return osVer
}

func referencesFromContains(sources []string, matches []string) []string {
	var references []string
	for _, s := range sources {
		for _, m := range matches {
			if strings.Contains(s, m) {
				references = append(references, s)
			}
		}
	}
	return ustrings.Unique(references)
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
