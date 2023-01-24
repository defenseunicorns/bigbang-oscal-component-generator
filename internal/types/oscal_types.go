/*
This file was auto-generated with go-oscal: https://github.com/defenseunicorns/go-oscal

One struct has been manually added to this file: OscalComponentDocument

This struct is needed to create the top-level "component-definition:" field
in the generated OSCAL component definition.
*/

package types

type Revision struct {
	Props        []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links        []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks      string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Title        string     `json:"title,omitempty" yaml:"title,omitempty"`
	Published    string     `json:"published,omitempty" yaml:"published,omitempty"`
	LastModified string     `json:"last-modified,omitempty" yaml:"last-modified,omitempty"`
	Version      string     `json:"version" yaml:"version"`
	OscalVersion string     `json:"oscal-version,omitempty" yaml:"oscal-version,omitempty"`
}
type Metadata struct {
	Version            string             `json:"version" yaml:"version"`
	OscalVersion       string             `json:"oscal-version" yaml:"oscal-version"`
	Props              []Property         `json:"props,omitempty" yaml:"props,omitempty"`
	Published          string             `json:"published,omitempty" yaml:"published,omitempty"`
	Revisions          []Revision         `json:"revisions,omitempty" yaml:"revisions,omitempty"`
	DocumentIds        []DocumentId       `json:"document-ids,omitempty" yaml:"document-ids,omitempty"`
	LastModified       string             `json:"last-modified" yaml:"last-modified"`
	Links              []Link             `json:"links,omitempty" yaml:"links,omitempty"`
	Parties            []Party            `json:"parties,omitempty" yaml:"parties,omitempty"`
	Remarks            string             `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Title              string             `json:"title" yaml:"title"`
	Roles              []Role             `json:"roles,omitempty" yaml:"roles,omitempty"`
	Locations          []Location         `json:"locations,omitempty" yaml:"locations,omitempty"`
	ResponsibleParties []ResponsibleParty `json:"responsible-parties,omitempty" yaml:"responsible-parties,omitempty"`
}
type ControlImplementation struct {
	ImplementedRequirements []ImplementedRequirement `json:"implemented-requirements" yaml:"implemented-requirements"`
	UUID                    string                   `json:"uuid" yaml:"uuid"`
	Source                  string                   `json:"source" yaml:"source"`
	Description             string                   `json:"description" yaml:"description"`
	Props                   []Property               `json:"props,omitempty" yaml:"props,omitempty"`
	Links                   []Link                   `json:"links,omitempty" yaml:"links,omitempty"`
	SetParameters           []SetParameter           `json:"set-parameters,omitempty" yaml:"set-parameters,omitempty"`
}
type IncorporatesComponent struct {
	ComponentUuid string `json:"component-uuid" yaml:"component-uuid"`
	Description   string `json:"description" yaml:"description"`
}
type BackMatter struct {
	Resources []Resources `json:"resources,omitempty" yaml:"resources,omitempty"`
}
type Link struct {
	Text      string `json:"text,omitempty" yaml:"text,omitempty"`
	Href      string `json:"href" yaml:"href"`
	Rel       string `json:"rel,omitempty" yaml:"rel,omitempty"`
	MediaType string `json:"media-type,omitempty" yaml:"media-type,omitempty"`
}
type PortRange struct {
	Start     int    `json:"start,omitempty" yaml:"start,omitempty"`
	End       int    `json:"end,omitempty" yaml:"end,omitempty"`
	Transport string `json:"transport,omitempty" yaml:"transport,omitempty"`
}

type OscalComponentDocument struct {
	ComponentDefinition ComponentDefinition `json:"component-definition" yaml:"component-definition"`
}

type ComponentDefinition struct {
	UUID                       string                      `json:"uuid" yaml:"uuid"`
	Metadata                   Metadata                    `json:"metadata" yaml:"metadata"`
	ImportComponentDefinitions []ImportComponentDefinition `json:"import-component-definitions,omitempty" yaml:"import-component-definitions,omitempty"`
	Components                 []DefinedComponent          `json:"components,omitempty" yaml:"components,omitempty"`
	Capabilities               []Capability                `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	BackMatter                 BackMatter                  `json:"back-matter,omitempty" yaml:"back-matter,omitempty"`
}
type ExternalIds struct {
	Scheme string `json:"scheme" yaml:"scheme"`
	ID     string `json:"id" yaml:"id"`
}
type Protocol struct {
	Title      string      `json:"title,omitempty" yaml:"title,omitempty"`
	PortRanges []PortRange `json:"port-ranges,omitempty" yaml:"port-ranges,omitempty"`
	UUID       string      `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Name       string      `json:"name" yaml:"name"`
}
type Citation struct {
	Text  string     `json:"text" yaml:"text"`
	Props []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links []Link     `json:"links,omitempty" yaml:"links,omitempty"`
}
type DefinedComponent struct {
	Props                  []Property              `json:"props,omitempty" yaml:"props,omitempty"`
	Links                  []Link                  `json:"links,omitempty" yaml:"links,omitempty"`
	ResponsibleRoles       []ResponsibleRole       `json:"responsible-roles,omitempty" yaml:"responsible-roles,omitempty"`
	Protocols              []Protocol              `json:"protocols,omitempty" yaml:"protocols,omitempty"`
	ControlImplementations []ControlImplementation `json:"control-implementations,omitempty" yaml:"control-implementations,omitempty"`
	Type                   string                  `json:"type" yaml:"type"`
	Description            string                  `json:"description" yaml:"description"`
	Purpose                string                  `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Remarks                string                  `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	UUID                   string                  `json:"uuid" yaml:"uuid"`
	Title                  string                  `json:"title" yaml:"title"`
}
type Rlinks struct {
	Href      string `json:"href" yaml:"href"`
	MediaType string `json:"media-type,omitempty" yaml:"media-type,omitempty"`
	Hashes    []Hash `json:"hashes,omitempty" yaml:"hashes,omitempty"`
}
type Address struct {
	City       string   `json:"city,omitempty" yaml:"city,omitempty"`
	State      string   `json:"state,omitempty" yaml:"state,omitempty"`
	PostalCode string   `json:"postal-code,omitempty" yaml:"postal-code,omitempty"`
	Country    string   `json:"country,omitempty" yaml:"country,omitempty"`
	Type       string   `json:"type,omitempty" yaml:"type,omitempty"`
	AddrLines  []string `json:"addr-lines,omitempty" yaml:"addr-lines,omitempty"`
}
type Hash struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Value     string `json:"value" yaml:"value"`
}
type TelephoneNumber struct {
	Type   string `json:"type,omitempty" yaml:"type,omitempty"`
	Number string `json:"number" yaml:"number"`
}
type Party struct {
	LocationUuids         []string          `json:"location-uuids,omitempty" yaml:"location-uuids,omitempty"`
	MemberOfOrganizations []string          `json:"member-of-organizations,omitempty" yaml:"member-of-organizations,omitempty"`
	Remarks               string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	UUID                  string            `json:"uuid" yaml:"uuid"`
	Name                  string            `json:"name,omitempty" yaml:"name,omitempty"`
	Props                 []Property        `json:"props,omitempty" yaml:"props,omitempty"`
	Links                 []Link            `json:"links,omitempty" yaml:"links,omitempty"`
	EmailAddresses        []string          `json:"email-addresses,omitempty" yaml:"email-addresses,omitempty"`
	TelephoneNumbers      []TelephoneNumber `json:"telephone-numbers,omitempty" yaml:"telephone-numbers,omitempty"`
	Addresses             []Address         `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Type                  string            `json:"type" yaml:"type"`
	ShortName             string            `json:"short-name,omitempty" yaml:"short-name,omitempty"`
	ExternalIds           []ExternalIds     `json:"external-ids,omitempty" yaml:"external-ids,omitempty"`
}
type ResponsibleParty struct {
	RoleId     string     `json:"role-id" yaml:"role-id"`
	PartyUuids []string   `json:"party-uuids" yaml:"party-uuids"`
	Props      []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links      []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks    string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}
type ImportComponentDefinition struct {
	Href string `json:"href" yaml:"href"`
}
type Capability struct {
	IncorporatesComponents []IncorporatesComponent `json:"incorporates-components,omitempty" yaml:"incorporates-components,omitempty"`
	ControlImplementations []ControlImplementation `json:"control-implementations,omitempty" yaml:"control-implementations,omitempty"`
	Remarks                string                  `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	UUID                   string                  `json:"uuid" yaml:"uuid"`
	Name                   string                  `json:"name" yaml:"name"`
	Description            string                  `json:"description" yaml:"description"`
	Props                  []Property              `json:"props,omitempty" yaml:"props,omitempty"`
	Links                  []Link                  `json:"links,omitempty" yaml:"links,omitempty"`
}
type Resources struct {
	UUID        string       `json:"uuid" yaml:"uuid"`
	Citation    []Citation   `json:"citation,omitempty" yaml:"citation,omitempty"`
	Rlinks      []Rlinks     `json:"rlinks,omitempty" yaml:"rlinks,omitempty"`
	Title       string       `json:"title,omitempty" yaml:"title,omitempty"`
	Description string       `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property   `json:"props,omitempty" yaml:"props,omitempty"`
	DocumentIds []DocumentId `json:"document-ids,omitempty" yaml:"document-ids,omitempty"`
	Base64      []Base64     `json:"base64,omitempty" yaml:"base64,omitempty"`
	Remarks     string       `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}
type DocumentId struct {
	Scheme     string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Identifier string `json:"identifier" yaml:"identifier"`
}
type Role struct {
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Props       []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links       []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks     string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	ID          string     `json:"id" yaml:"id"`
	Title       string     `json:"title" yaml:"title"`
	ShortName   string     `json:"short-name,omitempty" yaml:"short-name,omitempty"`
}
type Statement struct {
	StatementId      string            `json:"statement-id" yaml:"statement-id"`
	UUID             string            `json:"uuid" yaml:"uuid"`
	Description      string            `json:"description" yaml:"description"`
	Props            []Property        `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link            `json:"links,omitempty" yaml:"links,omitempty"`
	ResponsibleRoles []ResponsibleRole `json:"responsible-roles,omitempty" yaml:"responsible-roles,omitempty"`
	Remarks          string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}
type Base64 struct {
	Value     string `json:"value" yaml:"value"`
	Filename  string `json:"filename,omitempty" yaml:"filename,omitempty"`
	MediaType string `json:"media-type,omitempty" yaml:"media-type,omitempty"`
}
type Property struct {
	UUID    string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	Ns      string `json:"ns,omitempty" yaml:"ns,omitempty"`
	Value   string `json:"value" yaml:"value"`
	Class   string `json:"class,omitempty" yaml:"class,omitempty"`
	Remarks string `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Name    string `json:"name" yaml:"name"`
}
type Location struct {
	Title            string            `json:"title,omitempty" yaml:"title,omitempty"`
	Address          Address           `json:"address" yaml:"address"`
	EmailAddresses   []string          `json:"email-addresses,omitempty" yaml:"email-addresses,omitempty"`
	Urls             []string          `json:"urls,omitempty" yaml:"urls,omitempty"`
	UUID             string            `json:"uuid" yaml:"uuid"`
	TelephoneNumbers []TelephoneNumber `json:"telephone-numbers,omitempty" yaml:"telephone-numbers,omitempty"`
	Props            []Property        `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link            `json:"links,omitempty" yaml:"links,omitempty"`
	Remarks          string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}
type ResponsibleRole struct {
	Props      []Property `json:"props,omitempty" yaml:"props,omitempty"`
	Links      []Link     `json:"links,omitempty" yaml:"links,omitempty"`
	PartyUuids []string   `json:"party-uuids,omitempty" yaml:"party-uuids,omitempty"`
	Remarks    string     `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	RoleId     string     `json:"role-id" yaml:"role-id"`
}
type SetParameter struct {
	ParamId string   `json:"param-id" yaml:"param-id"`
	Values  []string `json:"values" yaml:"values"`
	Remarks string   `json:"remarks,omitempty" yaml:"remarks,omitempty"`
}
type ImplementedRequirement struct {
	ResponsibleRoles []ResponsibleRole `json:"responsible-roles,omitempty" yaml:"responsible-roles,omitempty"`
	Remarks          string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	UUID             string            `json:"uuid" yaml:"uuid"`
	Props            []Property        `json:"props,omitempty" yaml:"props,omitempty"`
	Links            []Link            `json:"links,omitempty" yaml:"links,omitempty"`
	SetParameters    []SetParameter    `json:"set-parameters,omitempty" yaml:"set-parameters,omitempty"`
	Statements       []Statement       `json:"statements,omitempty" yaml:"statements,omitempty"`
	ControlId        string            `json:"control-id" yaml:"control-id"`
	Description      string            `json:"description" yaml:"description"`
}
