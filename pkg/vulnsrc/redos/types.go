package redos

import "fmt"

type Definitions struct {
	Definition []Definition `json:"definition"`
}

type Definition struct {
	Metadata Metadata `json:"metadata"`
	Criteria Criteria `json:"criteria"`
	ID       string   `json:"id"`
	Version  string   `json:"version"`
	Class    string   `json:"class"`
}

type Metadata struct {
	Title        string      `json:"title"`
	AffectedList []Affected  `json:"affected"`
	References   []Reference `json:"reference"`
	Description  string      `json:"description"`
	Advisory     Advisory    `json:"advisory"`
}

type Affected struct {
	Platforms string `json:"platform"`
	Products  string `json:"product"`
	Family    string `json:"family"`
}

type Reference struct {
	Source string `json:"source"`
	RefID  string `json:"ref_id"`
	RefURL string `json:"ref_url"`
}

type Advisory struct {
	Severity        string          `json:"severity"`
	Issued          Issued          `json:"issued"`
	Updated         Updated         `json:"updated"`
	Cves            []CVE           `json:"cve"`
	AffectedCpeList AffectedCpeList `json:"affected_cpe_list"`
	From            string          `json:"from"`
}

type Issued struct {
	Date string `json:"date"`
}

type Updated struct {
	Date string `json:"date"`
}

type CVE struct {
	Cvss3 string `json:"cvss3"`
	Text  string `json:"text"`
}

type AffectedCpeList struct {
	Cpe []string `json:"cpe"`
}

type Criteria struct {
	Criterions []Criterion `json:"criterion"`
	Operator   string      `json:"operator"`
	Criterias  []Criteria  `json:"criteria"`
}

type Criterion struct {
	Comment string `json:"comment"`
	TestRef string `json:"test_ref"`
}

//type VulnerabilityDetail struct {
//	Description string `json:"description"`
//}

type AffectedPackage struct {
	Package Package
	OSVer   string
}

type Package struct {
	Name         string
	FixedVersion string
}

func (p *AffectedPackage) PlatformName() string {
	return fmt.Sprintf(platform, p.OSVer)
}
