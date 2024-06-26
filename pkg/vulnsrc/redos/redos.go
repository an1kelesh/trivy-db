package redos

import (
	"encoding/json"
	"fmt"
	version "github.com/knqyf263/go-rpm-version"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/an1kelesh/trivy-db/pkg/db"
	"github.com/an1kelesh/trivy-db/pkg/types"
	"github.com/an1kelesh/trivy-db/pkg/utils"
	ustrings "github.com/an1kelesh/trivy-db/pkg/utils/strings"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

var (
	platform        = "RedOS Linux %s"
	targetPlatforms = []string{"RedOS Linux 7.1", "RedOS Linux 7.2", "RedOS Linux 7.3"}
	redosDir        = filepath.Join("oval", "redos")

	source = types.DataSource{
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

func (vs *VulnSrc) parse(rootDir string) ([]Oval, error) {
	var ovals []Oval
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var oval Oval
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

func (vs *VulnSrc) put(ovals []Oval) error {
	log.Println("Saving RedOS Linux OVAL")

	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, ovals []Oval) error {
	for _, oval := range ovals {
		for _, ova := range oval.OvalDefinitions.Definitions.Definition {
			var vulnIDs []string
			for _, Reference := range ova.Metadata.Reference {
				vulnIDs = append(vulnIDs, Reference.RefID)
			}
			advisories := map[AffectedPackage]types.Advisory{}
			affectedPkg := walkRedOS(ova.Criteria, ova.Metadata.Affected, "", []AffectedPackage{})
			for _, affectedPkg := range affectedPkg {
				if affectedPkg.Package.Name == "" {
					continue
				}
				platformName := affectedPkg.PlatformName()
				if !ustrings.InSlice(platformName, targetPlatforms) {
					continue
				}
				if err := vs.PutDataSource(tx, platformName, source); err != nil {
					return xerrors.Errorf("failed to put data source: %w", err)
				}

				advisories[affectedPkg] = types.Advisory{
					FixedVersion: affectedPkg.Package.FixedVersion,
				}
			}

			var references []string
			for _, ref := range ova.Metadata.Reference {
				references = append(references, ref.RefURL)
			}

			for _, vulnID := range vulnIDs {
				vuln := types.VulnerabilityDetail{
					Description: ova.Metadata.Description,
					References:  referencesFromContains(references, []string{vulnID}),
					Title:       ova.Metadata.Title,
					Severity:    severityFromThreat(ova.Metadata.Advisory.Severity),
				}

				err := vs.Put(tx, PutInput{
					VulnID:     vulnID,
					Vuln:       vuln,
					Advisories: advisories,
					OVAL:       ova,
				})
				if err != nil {
					return xerrors.Errorf("db put error: %w", err)
				}
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

func walkRedOS(cri Criteria, affect Affected, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	if strings.HasPrefix(affect.Platform, "RED OS") {
		osVer = strings.TrimPrefix(affect.Platform, "RED OS ")
	}
	ss := strings.Split(cri.Criterion.Comment, " version is less than ")
	pkgs = append(pkgs, AffectedPackage{
		OSVer: osVer,
		Package: Package{
			Name:         ss[0],
			FixedVersion: version.NewVersion(ss[1]).String(),
		},
	})
	for _, c := range cri.Criterias {
		pkgs = walkRedOS(c, affect, osVer, pkgs)
	}
	return pkgs
}

//func walkRedOSver(affect Affected, osVer string) string {
//	for _, d := range affect.Platform {
//		if strings.HasPrefix(string(d), "RED OS ") {
//			osVer = strings.TrimPrefix(string(d), "RED OS ")
//		}
//	}
//	return osVer
//}

func referencesFromContains(sources []string, matches []string) []string {
	var references []string
	for _, s := range sources {
		for _, m := range matches {
			if strings.Contains(s, "redos") && strings.Contains(m, "ROS") {
				references = append(references, s)
			}
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
