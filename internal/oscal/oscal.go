package oscal

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"gopkg.in/yaml.v2"
)

func GetOscalComponentDocumentFromRepo(repo string, tag string) (types.ComponentDefinition, error) {
	var document types.ComponentDefinition
	repo = strings.Replace(repo, ".git", "", -1)
	rawUrl := fmt.Sprintf("%s/-/raw/%s/oscal-component.yaml", repo, tag)
	uri, err := url.Parse(rawUrl)
	if err != nil {
		return document, err
	}
	responseCode, bytes, err := http.FetchFromHTTPResource(uri)
	if err != nil {
		return document, err
	}
	if responseCode != 200 {
		return document, fmt.Errorf("unexpected response code when downloading document: %v", responseCode)
	}
	err = yaml.Unmarshal(bytes, &document)
	if err != nil {
		return document, err
	}

	return document, nil
}
