package mariner

import "github.com/wjunLu/trivy-db/pkg/vulnsrc/mariner/oval"

type operator string

type Entry struct {
	PkgName  string
	Version  string
	Operator operator
	Metadata oval.Metadata
}
