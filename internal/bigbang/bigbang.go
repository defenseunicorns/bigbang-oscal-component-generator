package bigbang

import (
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/oscal"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"gopkg.in/yaml.v2"
	"net/url"
)

func GetAllBigBangSubchartOscalComponentDocuments() ([]types.OscalComponentDocument, error) {
	var components []types.OscalComponentDocument
	bigBangValues, err := getBigBangValues()
	if err != nil {
		return nil, err
	}
	// Core
	component, err := oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Istio.Git.Repo, bigBangValues.Istio.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Istiooperator.Git.Repo, bigBangValues.Istiooperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Jaeger.Git.Repo, bigBangValues.Jaeger.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Kiali.Git.Repo, bigBangValues.Kiali.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.ClusterAuditor.Git.Repo, bigBangValues.ClusterAuditor.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Gatekeeper.Git.Repo, bigBangValues.Gatekeeper.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Kyverno.Git.Repo, bigBangValues.Kyverno.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Kyvernopolicies.Git.Repo, bigBangValues.Kyvernopolicies.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Logging.Git.Repo, bigBangValues.Logging.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Eckoperator.Git.Repo, bigBangValues.Eckoperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Fluentbit.Git.Repo, bigBangValues.Fluentbit.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Promtail.Git.Repo, bigBangValues.Promtail.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Loki.Git.Repo, bigBangValues.Loki.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Tempo.Git.Repo, bigBangValues.Tempo.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Monitoring.Git.Repo, bigBangValues.Monitoring.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Twistlock.Git.Repo, bigBangValues.Twistlock.Git.Tag)
	if err == nil {
		components = append(components, component)
	}

	// Addons
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Argocd.Git.Repo, bigBangValues.Addons.Argocd.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Authservice.Git.Repo, bigBangValues.Addons.Authservice.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.MinioOperator.Git.Repo, bigBangValues.Addons.MinioOperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Minio.Git.Repo, bigBangValues.Addons.Minio.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Gitlab.Git.Repo, bigBangValues.Addons.Gitlab.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.GitlabRunner.Git.Repo, bigBangValues.Addons.GitlabRunner.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Nexus.Git.Repo, bigBangValues.Addons.Nexus.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Sonarqube.Git.Repo, bigBangValues.Addons.Sonarqube.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Haproxy.Git.Repo, bigBangValues.Addons.Haproxy.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Anchore.Git.Repo, bigBangValues.Addons.Anchore.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Mattermostoperator.Git.Repo, bigBangValues.Addons.Mattermostoperator.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Mattermost.Git.Repo, bigBangValues.Addons.Mattermost.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Velero.Git.Repo, bigBangValues.Addons.Velero.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Keycloak.Git.Repo, bigBangValues.Addons.Keycloak.Git.Tag)
	if err == nil {
		components = append(components, component)
	}
	component, err = oscal.GetOscalComponentDocumentFromRepo(bigBangValues.Addons.Vault.Git.Repo, bigBangValues.Addons.Vault.Git.Tag)
	if err == nil {
		components = append(components, component)
	}

	return components, nil
}

func getBigBangValues() (types.BigBangValues, error) {
	var bbValues types.BigBangValues
	fileUrl := "https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/values.yaml"
	uri, err := url.Parse(fileUrl)
	if err != nil {
		return bbValues, err
	}
	bytes, err := http.FetchFromHTTPResource(uri)
	if err != nil {
		return bbValues, err
	}
	err = yaml.Unmarshal(bytes, &bbValues)
	if err != nil {
		return bbValues, err
	}
	return bbValues, nil
}
