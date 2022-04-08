package yaml

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	network "github.com/defenseunicorns/bigbang-oscal-component-generator/internal/utils"
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
	bigBangValues, err := getBigBangValuesYaml()
	if err != nil {
		return nil, err
	}
	// Core
	component, err := getOscalComponentYaml(bigBangValues.Istio.Git.Repo, bigBangValues.Istio.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Istiooperator.Git.Repo, bigBangValues.Istiooperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Jaeger.Git.Repo, bigBangValues.Jaeger.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Kiali.Git.Repo, bigBangValues.Kiali.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.ClusterAuditor.Git.Repo, bigBangValues.ClusterAuditor.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Gatekeeper.Git.Repo, bigBangValues.Gatekeeper.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Kyverno.Git.Repo, bigBangValues.Kyverno.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Kyvernopolicies.Git.Repo, bigBangValues.Kyvernopolicies.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Logging.Git.Repo, bigBangValues.Logging.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Eckoperator.Git.Repo, bigBangValues.Eckoperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Fluentbit.Git.Repo, bigBangValues.Fluentbit.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Promtail.Git.Repo, bigBangValues.Promtail.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Loki.Git.Repo, bigBangValues.Loki.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Tempo.Git.Repo, bigBangValues.Tempo.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Monitoring.Git.Repo, bigBangValues.Monitoring.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Twistlock.Git.Repo, bigBangValues.Twistlock.Git.Tag)
	if err == nil {
		components = append(components, component)
	}

	// Addons
	component, err = getOscalComponentYaml(bigBangValues.Addons.Argocd.Git.Repo, bigBangValues.Addons.Argocd.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Authservice.Git.Repo, bigBangValues.Addons.Authservice.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.MinioOperator.Git.Repo, bigBangValues.Addons.MinioOperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Minio.Git.Repo, bigBangValues.Addons.Minio.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Gitlab.Git.Repo, bigBangValues.Addons.Gitlab.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.GitlabRunner.Git.Repo, bigBangValues.Addons.GitlabRunner.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Nexus.Git.Repo, bigBangValues.Addons.Nexus.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Sonarqube.Git.Repo, bigBangValues.Addons.Sonarqube.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Haproxy.Git.Repo, bigBangValues.Addons.Haproxy.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Anchore.Git.Repo, bigBangValues.Addons.Anchore.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Mattermostoperator.Git.Repo, bigBangValues.Addons.Mattermostoperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Mattermost.Git.Repo, bigBangValues.Addons.Mattermost.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Velero.Git.Repo, bigBangValues.Addons.Velero.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Keycloak.Git.Repo, bigBangValues.Addons.Keycloak.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = getOscalComponentYaml(bigBangValues.Addons.Vault.Git.Repo, bigBangValues.Addons.Vault.Git.Tag)
	if err == nil {
		components = append(components, component)
	}

	return components, nil
}

func getBigBangValuesYaml() (types.BigBangValues, error) {
	var bbValues types.BigBangValues
	fileUrl := "https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/values.yaml"
	uri, err := url.Parse(fileUrl)
	if err != nil {
		return bbValues, fmt.Errorf("invalid URL pattern %v", err)
	}
	bytes, err := network.FetchFromHTTPResource(uri)
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
	bytes, err := network.FetchFromHTTPResource(uri)
	if err != nil {
		return component, err
	}
	err = yaml.Unmarshal(bytes, &component)
	if err != nil {
		return component, err
	}
	return component, nil
}
