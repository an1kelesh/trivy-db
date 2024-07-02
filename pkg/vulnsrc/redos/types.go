package redos

import "fmt"

type Oval struct {
	OvalDefinitions OvalDefinitions `json:"oval_definitions"`
}

type OvalDefinitions struct {
	Definitions Definitions `json:"definitions"`
}

type ProductName struct {
	Prefix string `json:"__prefix"`
	Text   string `json:"__text"`
}

type SchemaVersion struct {
	Prefix string `json:"__prefix"`
	Text   string `json:"__text"`
}

type Timestamp struct {
	Prefix string `json:"__prefix"`
	Text   string `json:"__text"`
}

type Definitions struct {
	Definition []Definition `json:"definition"`
}

type Definition struct {
	Metadata Metadata `json:"metadata"`
	Criteria Criteria `json:"criteria"`
	ID       string   `json:"_id"`
	Version  string   `json:"_version"`
	Class    string   `json:"_class"`
}

type Metadata struct {
	Title       string      `json:"title"`
	Affected    Affected    `json:"affected"`
	Reference   []Reference `json:"reference"`
	Description string      `json:"description"`
	Advisory    Advisory    `json:"advisory"`
}

type Affected struct {
	Platform string `json:"platform"`
	Product  string `json:"product"`
	Family   string `json:"_family"`
	Affect   []Affected
}

type Reference struct {
	Source string `json:"_source"`
	RefID  string `json:"_ref_id"`
	RefURL string `json:"_ref_url"`
}

type Advisory struct {
	Severity        string          `json:"severity"`
	Issued          Issued          `json:"issued"`
	Updated         Updated         `json:"updated"`
	Cve             Cve             `json:"cve"`
	AffectedCpeList AffectedCpeList `json:"affected_cpe_list"`
	From            string          `json:"_from"`
}

type Issued struct {
	Date string `json:"_date"`
}

type Updated struct {
	Date string `json:"_date"`
}

type Cve struct {
	Cvss3 string `json:"_cvss3"`
	Text  string `json:"__text"`
}

type AffectedCpeList struct {
	Cpe string `json:"cpe"`
}

type Criteria struct {
	Criterion Criterion `json:"criterion"`
	Operator  string    `json:"_operator"`
	Criterias []Criteria
}

type Criterion struct {
	Comment string `json:"_comment"`
	TestRef string `json:"_test_ref"`
}

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
