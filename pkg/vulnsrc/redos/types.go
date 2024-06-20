package redos

import "fmt"

type Oval struct {
	OvalDefinitions OvalDefinitions `json:"oval_definitions"`
}

type OvalDefinitions struct {
	Generator         Generator   `json:"generator"`
	Definitions       Definitions `json:"definitions"`
	Tests             Tests       `json:"tests"`
	Objects           Objects     `json:"objects"`
	States            States      `json:"states"`
	Xmlns             string      `json:"_xmlns"`
	XmlnsXsi          string      `json:"_xmlns:xsi"`
	XmlnsOval         string      `json:"_xmlns:oval"`
	XmlnsOvalDef      string      `json:"_xmlns:oval-def"`
	XsiSchemaLocation string      `json:"_xsi:schemaLocation"`
}

type Generator struct {
	ProductName   ProductName   `json:"product_name"`
	SchemaVersion SchemaVersion `json:"schema_version"`
	Timestamp     Timestamp     `json:"timestamp"`
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

type Tests struct {
	RpminfoTest []RpminfoTest `json:"rpminfo_test"`
}

type RpminfoTest struct {
	Object         Object `json:"object"`
	State          State  `json:"state"`
	Xmlns          string `json:"_xmlns"`
	ID             string `json:"_id"`
	Version        string `json:"_version"`
	Check          string `json:"_check"`
	CheckExistence string `json:"_check_existence"`
	Comment        string `json:"_comment"`
}

type Object struct {
	ObjectRef string `json:"_object_ref"`
}

type State struct {
	StateRef string `json:"_state_ref"`
}

type Objects struct {
	RpminfoObject []RpminfoObject `json:"rpminfo_object"`
}

type RpminfoObject struct {
	Name    string `json:"name"`
	Xmlns   string `json:"_xmlns"`
	ID      string `json:"_id"`
	Version string `json:"_version"`
}

type States struct {
	RpminfoState []RpminfoState `json:"rpminfo_state"`
}

type RpminfoState struct {
	Evr     Evr    `json:"evr"`
	Xmlns   string `json:"_xmlns"`
	ID      string `json:"_id"`
	Version string `json:"_version"`
}

type Evr struct {
	Datatype  string `json:"_datatype"`
	Operation string `json:"_operation"`
	Text      string `json:"__text"`
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
