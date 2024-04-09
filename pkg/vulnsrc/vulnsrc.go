package vulnsrc

import (
	"github.com/wjunLu/trivy-db/pkg/types"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/alma"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/alpine"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/amazon"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/bitnami"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/bundler"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/composer"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/debian"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/glad"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/mariner"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/node"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/wjunLu/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/photon"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/wjunLu/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/wjunLu/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/wolfi"
	"github.com/wjunLu/trivy-db/pkg/vulnsrc/openeuler"
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
		openeuler.NewVulnSrc(),

		k8svulndb.NewVulnSrc(),
		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
	}
)
