package vulnsrc

import (
	"github.com/an1kelesh/trivy-db/pkg/types"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/alma"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/alpine"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/amazon"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/bitnami"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/bundler"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/composer"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/debian"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/glad"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/govulndb"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/mariner"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/node"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/redos"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/an1kelesh/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/photon"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/an1kelesh/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/an1kelesh/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/an1kelesh/trivy-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []VulnSrc{
		// NVD
		nvd.NewVulnSrc(),

		// OS packages
		alma.NewVulnSrc(),
		alpine.NewVulnSrc(),
		redhat.NewVulnSrc(),
		redhatoval.NewVulnSrc(),
		redos.NewVulnSrc(),
		debian.NewVulnSrc(),
		ubuntu.NewVulnSrc(),
		amazon.NewVulnSrc(),
		oracleoval.NewVulnSrc(),
		rocky.NewVulnSrc(),
		susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		photon.NewVulnSrc(),
		mariner.NewVulnSrc(),
		wolfi.NewVulnSrc(),
		chainguard.NewVulnSrc(),
		bitnami.NewVulnSrc(),

		k8svulndb.NewVulnSrc(),

		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
		govulndb.NewVulnSrc(), // For Go stdlib packages
	}
)
