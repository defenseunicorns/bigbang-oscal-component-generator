package nist

import (
	"fmt"
	"log"
	"net/url"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"gopkg.in/yaml.v2"
)

var NIST80053 Nist80053Catalog

func init() {
	var err error
	NIST80053, err = LoadNist80053Catalog()
	if err != nil {
		log.Fatal(err)
	}
}

type Nist80053Catalog struct {
	Catalog struct {
		UUID     string `yaml:"uuid"`
		Metadata struct {
			Title        string `yaml:"title"`
			LastModified struct {
			} `yaml:"last-modified"`
			Version      string `yaml:"version"`
			OscalVersion string `yaml:"oscal-version"`
			Props        []struct {
				Name  string `yaml:"name"`
				Value string `yaml:"value"`
			} `yaml:"props"`
			Links []struct {
				Href string `yaml:"href"`
				Rel  string `yaml:"rel"`
			} `yaml:"links"`
			Roles []struct {
				ID    string `yaml:"id"`
				Title string `yaml:"title"`
			} `yaml:"roles"`
			Parties []struct {
				UUID           string   `yaml:"uuid"`
				Type           string   `yaml:"type"`
				Name           string   `yaml:"name"`
				EmailAddresses []string `yaml:"email-addresses"`
				Addresses      []struct {
					AddrLines  []string `yaml:"addr-lines"`
					City       string   `yaml:"city"`
					State      string   `yaml:"state"`
					PostalCode string   `yaml:"postal-code"`
				} `yaml:"addresses"`
			} `yaml:"parties"`
			ResponsibleParties []struct {
				RoleID     string   `yaml:"role-id"`
				PartyUuids []string `yaml:"party-uuids"`
			} `yaml:"responsible-parties"`
		} `yaml:"metadata"`
		Groups []struct {
			ID       string `yaml:"id"`
			Class    string `yaml:"class"`
			Title    string `yaml:"title"`
			Controls []struct {
				ID     string `yaml:"id"`
				Class  string `yaml:"class"`
				Title  string `yaml:"title"`
				Params []struct {
					ID    string `yaml:"id"`
					Props []struct {
						Name  string `yaml:"name"`
						Ns    string `yaml:"ns"`
						Value string `yaml:"value"`
					} `yaml:"props"`
					Label      string `yaml:"label,omitempty"`
					Guidelines []struct {
						Prose string `yaml:"prose"`
					} `yaml:"guidelines,omitempty"`
					Select struct {
						HowMany string   `yaml:"how-many"`
						Choice  []string `yaml:"choice"`
					} `yaml:"select,omitempty"`
				} `yaml:"params,omitempty"`
				Props []struct {
					Name  string `yaml:"name"`
					Value string `yaml:"value"`
					Class string `yaml:"class,omitempty"`
				} `yaml:"props"`
				Links []struct {
					Href string `yaml:"href"`
					Rel  string `yaml:"rel"`
				} `yaml:"links"`
				Parts []struct {
					ID    string `yaml:"id"`
					Name  string `yaml:"name"`
					Parts []struct {
						ID    string `yaml:"id"`
						Name  string `yaml:"name"`
						Props []struct {
							Name  string `yaml:"name"`
							Value string `yaml:"value"`
						} `yaml:"props"`
						Prose string `yaml:"prose"`
						Parts []struct {
							ID    string `yaml:"id"`
							Name  string `yaml:"name"`
							Props []struct {
								Name  string `yaml:"name"`
								Value string `yaml:"value"`
							} `yaml:"props"`
							Prose string `yaml:"prose"`
							Parts []struct {
								ID    string `yaml:"id"`
								Name  string `yaml:"name"`
								Props []struct {
									Name  string `yaml:"name"`
									Value string `yaml:"value"`
								} `yaml:"props"`
								Prose string `yaml:"prose"`
							} `yaml:"parts,omitempty"`
						} `yaml:"parts,omitempty"`
					} `yaml:"parts,omitempty"`
					Prose string `yaml:"prose,omitempty"`
					Props []struct {
						Name  string `yaml:"name"`
						Value string `yaml:"value"`
						Class string `yaml:"class"`
					} `yaml:"props,omitempty"`
				} `yaml:"parts,omitempty"`
				Controls []struct {
					ID     string `yaml:"id"`
					Class  string `yaml:"class"`
					Title  string `yaml:"title"`
					Params []struct {
						ID    string `yaml:"id"`
						Props []struct {
							Name  string `yaml:"name"`
							Value string `yaml:"value"`
							Class string `yaml:"class,omitempty"`
						} `yaml:"props"`
						Label      string `yaml:"label"`
						Guidelines []struct {
							Prose string `yaml:"prose"`
						} `yaml:"guidelines"`
					} `yaml:"params,omitempty"`
					Props []struct {
						Name  string `yaml:"name"`
						Value string `yaml:"value"`
						Class string `yaml:"class,omitempty"`
					} `yaml:"props"`
					Links []struct {
						Href string `yaml:"href"`
						Rel  string `yaml:"rel"`
					} `yaml:"links"`
					Parts []struct {
						ID    string `yaml:"id"`
						Name  string `yaml:"name"`
						Prose string `yaml:"prose,omitempty"`
						Props []struct {
							Name  string `yaml:"name"`
							Value string `yaml:"value"`
							Class string `yaml:"class"`
						} `yaml:"props,omitempty"`
						Parts []struct {
							Name  string `yaml:"name"`
							Prose string `yaml:"prose"`
						} `yaml:"parts,omitempty"`
					} `yaml:"parts,omitempty"`
				} `yaml:"controls,omitempty"`
			} `yaml:"controls"`
			Parts []struct {
				ID    string `yaml:"id"`
				Name  string `yaml:"name"`
				Title string `yaml:"title"`
				Prose string `yaml:"prose"`
			} `yaml:"parts,omitempty"`
		} `yaml:"groups"`
		BackMatter struct {
			Resources []struct {
				UUID     string `yaml:"uuid"`
				Title    string `yaml:"title"`
				Citation struct {
					Text string `yaml:"text"`
				} `yaml:"citation,omitempty"`
				Rlinks []struct {
					Href string `yaml:"href"`
				} `yaml:"rlinks,omitempty"`
			} `yaml:"resources"`
		} `yaml:"back-matter"`
	} `yaml:"catalog"`
}

func LoadNist80053Catalog() (Nist80053Catalog, error) {
	var catalog Nist80053Catalog
	fileUrl := "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/yaml/NIST_SP-800-53_rev5_catalog.yaml"
	uri, err := url.Parse(fileUrl)
	if err != nil {
		return catalog, err
	}
	bytes, err := http.FetchFromHTTPResource(uri)
	if err != nil {
		return catalog, err
	}
	err = yaml.Unmarshal(bytes, &catalog)
	if err != nil {
		return catalog, err
	}
	return catalog, nil
}

// GetControlInformationFromControlID returns the control Title and the control Information
func GetControlInformationFromControlID(id string) (string, string, error) {
	for _, group := range NIST80053.Catalog.Groups {
		for _, control := range group.Controls {
			if control.ID == id {
				return group.Title, control.Parts[0].Prose, nil
			}
		}
	}
	return "", "", fmt.Errorf("Control ID %v not found", id)
}

//func GetLabelByControlId(catalog *Nist80053Catalog, controlId string) (string, error) {
//	idx := slices.IndexFunc(catalog.Catalog.Groups, func(c Config) bool { return c.Key == "key1" })
//}
