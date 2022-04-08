package yaml

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/utils"
	"gopkg.in/yaml.v2"
)

func BuildBigBangOscalComponentDocument() (string, error) {
	var document types.OscalComponentDocument
	components, err := getAllOscalComponents()
	if err != nil {
		return "", err
	}
	document.ComponentDefinition.Components = components
	bytes, err := yaml.Marshal(&document)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func getAllOscalComponents() ([]types.OscalComponent, error) {
	var components []types.OscalComponent
	documents, err := getAllOscalComponentDocuments()
	if err != nil {
		return nil, err
	}
	for _, document := range documents {
		components = append(components, document.ComponentDefinition.Components...)
	}
	return components, nil
}

func getAllOscalComponentDocuments() ([]types.OscalComponentDocument, error) {
	var components []types.OscalComponentDocument
	bigBangValues, err := GetBigBangValuesYaml()
	if err != nil {
		return nil, err
	}
	gits := utils.ExtractGit(bigBangValues)
	for _, git := range gits {
		component, _ := getOscalComponentYaml(git.Repo, git.Tag)
		components = append(components, component)
	}
	return components, nil
}

func GetBigBangValuesYaml() (types.BigBangValues, error) {
	var bbValues types.BigBangValues
	fileUrl := "https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/values.yaml"
	uri, err := url.Parse(fileUrl)
	if err != nil {
		return bbValues, fmt.Errorf("invalid URL pattern %v", err)
	}
	bytes, err := utils.FetchFromHTTPResource(uri)
	if err != nil {
		return bbValues, err
	}
	yaml.Unmarshal(bytes, &bbValues)
	return bbValues, nil
}

func getOscalComponentYaml(repo string, tag string) (types.OscalComponentDocument, error) {
	var component types.OscalComponentDocument
	repo = strings.Replace(repo, ".git", "", -1)
	rawUrl := fmt.Sprintf("%s/-/raw/%s/oscal-component.yaml", repo, tag)
	uri, err := url.Parse(rawUrl)
	if err != nil {
		return component, err
	}
	bytes, err := utils.FetchFromHTTPResource(uri)
	if err != nil {
		return component, err
	}
	err = yaml.Unmarshal(bytes, &component)
	if err != nil {
		return component, err
	}
	return component, nil
}
