package oscal

import (
	"fmt"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"gopkg.in/yaml.v2"
	"net/url"
	"strings"
	"time"
)

type OscalComponentDocument struct {
	ComponentDefinition struct {
		UUID     string `yaml:"uuid"`
		Metadata struct {
			Title        string    `yaml:"title"`
			LastModified time.Time `yaml:"last-modified"`
			Version      int       `yaml:"version"`
			OscalVersion string    `yaml:"oscal-version"`
			Parties      []struct {
				UUID  string `yaml:"uuid"`
				Type  string `yaml:"type"`
				Name  string `yaml:"name"`
				Links []struct {
					Href string `yaml:"href"`
					Rel  string `yaml:"rel"`
				} `yaml:"links"`
			} `yaml:"parties"`
		} `yaml:"metadata"`
		Components []OscalComponent `yaml:"components"`
		BackMatter struct {
			Resources []struct {
				UUID   string `yaml:"uuid"`
				Title  string `yaml:"title"`
				Rlinks []struct {
					Href string `yaml:"href"`
				} `yaml:"rlinks"`
			} `yaml:"resources"`
		} `yaml:"back-matter"`
	} `yaml:"component-definition"`
}

type OscalComponent struct {
	UUID             string `yaml:"uuid"`
	Type             string `yaml:"type"`
	Title            string `yaml:"title"`
	Description      string `yaml:"description"`
	Purpose          string `yaml:"purpose"`
	ResponsibleRoles []struct {
		RoleID    string `yaml:"role-id"`
		PartyUUID string `yaml:"party-uuid"`
	} `yaml:"responsible-roles"`
	ControlImplementations []struct {
		UUID                    string `yaml:"uuid"`
		Source                  string `yaml:"source"`
		Description             string `yaml:"description"`
		ImplementedRequirements []struct {
			UUID        string `yaml:"uuid"`
			ControlID   string `yaml:"control-id"`
			Description string `yaml:"description"`
		} `yaml:"implemented-requirements"`
	} `yaml:"control-implementations"`
}

func GetOscalComponentDocumentFromRepo(repo string, tag string) (OscalComponentDocument, error) {
	var document OscalComponentDocument
	repo = strings.Replace(repo, ".git", "", -1)
	rawUrl := fmt.Sprintf("%s/-/raw/%s/oscal-component.yaml", repo, tag)
	uri, err := url.Parse(rawUrl)
	if err != nil {
		return document, err
	}
	bytes, err := http.FetchFromHTTPResource(uri)
	if err != nil {
		return document, err
	}
	err = yaml.Unmarshal(bytes, &document)
	if err != nil {
		return document, err
	}

	return document, nil
}
