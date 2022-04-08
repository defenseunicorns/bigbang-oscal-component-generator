package bigbang

import (
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/oscal"
	"gopkg.in/yaml.v2"
	"net/url"
)

type BigBangValues struct {
	Domain              string `yaml:"domain"`
	Offline             bool   `yaml:"offline"`
	RegistryCredentials struct {
		Registry string `yaml:"registry"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Email    string `yaml:"email"`
	} `yaml:"registryCredentials"`
	Openshift bool `yaml:"openshift"`
	Git       struct {
		ExistingSecret string `yaml:"existingSecret"`
		Credentials    struct {
			Username   string `yaml:"username"`
			Password   string `yaml:"password"`
			CaFile     string `yaml:"caFile"`
			PrivateKey string `yaml:"privateKey"`
			PublicKey  string `yaml:"publicKey"`
			KnownHosts string `yaml:"knownHosts"`
		} `yaml:"credentials"`
	} `yaml:"git"`
	Sso struct {
		Oidc struct {
			Host  string `yaml:"host"`
			Realm string `yaml:"realm"`
		} `yaml:"oidc"`
		CertificateAuthority string `yaml:"certificate_authority"`
		Jwks                 string `yaml:"jwks"`
		ClientID             string `yaml:"client_id"`
		ClientSecret         string `yaml:"client_secret"`
		TokenURL             string `yaml:"token_url"`
		AuthURL              string `yaml:"auth_url"`
		SecretName           string `yaml:"secretName"`
	} `yaml:"sso"`
	Flux struct {
		Timeout  string `yaml:"timeout"`
		Interval string `yaml:"interval"`
		Test     struct {
			Enable bool `yaml:"enable"`
		} `yaml:"test"`
		Install struct {
			Remediation struct {
				Retries int `yaml:"retries"`
			} `yaml:"remediation"`
		} `yaml:"install"`
		Upgrade struct {
			Remediation struct {
				Retries              int  `yaml:"retries"`
				RemediateLastFailure bool `yaml:"remediateLastFailure"`
			} `yaml:"remediation"`
			CleanupOnFail bool `yaml:"cleanupOnFail"`
		} `yaml:"upgrade"`
		Rollback struct {
			Timeout       string `yaml:"timeout"`
			CleanupOnFail bool   `yaml:"cleanupOnFail"`
		} `yaml:"rollback"`
	} `yaml:"flux"`
	NetworkPolicies struct {
		Enabled          bool   `yaml:"enabled"`
		ControlPlaneCidr string `yaml:"controlPlaneCidr"`
		NodeCidr         string `yaml:"nodeCidr"`
		VpcCidr          string `yaml:"vpcCidr"`
	} `yaml:"networkPolicies"`
	ImagePullPolicy string `yaml:"imagePullPolicy"`
	Istio           struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Enterprise      bool `yaml:"enterprise"`
		IngressGateways struct {
			PublicIngressgateway struct {
				Type                   string `yaml:"type"`
				KubernetesResourceSpec struct {
				} `yaml:"kubernetesResourceSpec"`
			} `yaml:"public-ingressgateway"`
		} `yaml:"ingressGateways"`
		Gateways struct {
			Public struct {
				IngressGateway   string   `yaml:"ingressGateway"`
				Hosts            []string `yaml:"hosts"`
				AutoHTTPRedirect struct {
					Enabled bool `yaml:"enabled"`
				} `yaml:"autoHttpRedirect"`
				TLS struct {
					Key  string `yaml:"key"`
					Cert string `yaml:"cert"`
				} `yaml:"tls"`
			} `yaml:"public"`
		} `yaml:"gateways"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"istio"`
	Istiooperator struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"istiooperator"`
	Jaeger struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
			Install struct {
				Crds string `yaml:"crds"`
			} `yaml:"install"`
			Upgrade struct {
				Crds string `yaml:"crds"`
			} `yaml:"upgrade"`
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Sso struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"sso"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"jaeger"`
	Kiali struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Sso struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"sso"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kiali"`
	ClusterAuditor struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"clusterAuditor"`
	Gatekeeper struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
			Install struct {
				Crds string `yaml:"crds"`
			} `yaml:"install"`
			Upgrade struct {
				Crds string `yaml:"crds"`
			} `yaml:"upgrade"`
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"gatekeeper"`
	Kyverno struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kyverno"`
	Kyvernopolicies struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kyvernopolicies"`
	Logging struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
			Timeout string `yaml:"timeout"`
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Sso struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"sso"`
		License struct {
			Trial   bool   `yaml:"trial"`
			KeyJSON string `yaml:"keyJSON"`
		} `yaml:"license"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"logging"`
	Eckoperator struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
	} `yaml:"eckoperator"`
	Fluentbit struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"fluentbit"`
	Promtail struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"promtail"`
	Loki struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"loki"`
	Tempo struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"tempo"`
	Monitoring struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
			Install struct {
				Crds string `yaml:"crds"`
			} `yaml:"install"`
			Upgrade struct {
				Crds string `yaml:"crds"`
			} `yaml:"upgrade"`
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Sso struct {
			Enabled    bool `yaml:"enabled"`
			Prometheus struct {
				ClientID     string `yaml:"client_id"`
				ClientSecret string `yaml:"client_secret"`
			} `yaml:"prometheus"`
			Alertmanager struct {
				ClientID     string `yaml:"client_id"`
				ClientSecret string `yaml:"client_secret"`
			} `yaml:"alertmanager"`
			Grafana struct {
				ClientID          string `yaml:"client_id"`
				ClientSecret      string `yaml:"client_secret"`
				Scopes            string `yaml:"scopes"`
				AllowSignUp       string `yaml:"allow_sign_up"`
				RoleAttributePath string `yaml:"role_attribute_path"`
			} `yaml:"grafana"`
		} `yaml:"sso"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"monitoring"`
	Twistlock struct {
		Enabled bool `yaml:"enabled"`
		Git     struct {
			Repo string `yaml:"repo"`
			Path string `yaml:"path"`
			Tag  string `yaml:"tag"`
		} `yaml:"git"`
		Flux struct {
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"twistlock"`
	Addons struct {
		Argocd struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Redis struct {
				Host string `yaml:"host"`
				Port string `yaml:"port"`
			} `yaml:"redis"`
			Sso struct {
				Enabled      bool   `yaml:"enabled"`
				ClientID     string `yaml:"client_id"`
				ClientSecret string `yaml:"client_secret"`
				ProviderName string `yaml:"provider_name"`
				Groups       string `yaml:"groups"`
			} `yaml:"sso"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"argocd"`
		Authservice struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
			Chains        struct {
			} `yaml:"chains"`
		} `yaml:"authservice"`
		MinioOperator struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"minioOperator"`
		Minio struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Accesskey string `yaml:"accesskey"`
			Secretkey string `yaml:"secretkey"`
			Values    struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"minio"`
		Gitlab struct {
			Enabled   bool `yaml:"enabled"`
			Hostnames struct {
				Gitlab   string `yaml:"gitlab"`
				Registry string `yaml:"registry"`
			} `yaml:"hostnames"`
			Git struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Sso struct {
				Enabled       bool     `yaml:"enabled"`
				ClientID      string   `yaml:"client_id"`
				ClientSecret  string   `yaml:"client_secret"`
				Label         string   `yaml:"label"`
				Scopes        []string `yaml:"scopes"`
				IssuerURI     string   `yaml:"issuer_uri"`
				EndSessionURI string   `yaml:"end_session_uri"`
				UIDField      string   `yaml:"uid_field"`
			} `yaml:"sso"`
			Database struct {
				Host     string `yaml:"host"`
				Port     int    `yaml:"port"`
				Database string `yaml:"database"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			} `yaml:"database"`
			ObjectStorage struct {
				Type         string `yaml:"type"`
				Endpoint     string `yaml:"endpoint"`
				Region       string `yaml:"region"`
				AccessKey    string `yaml:"accessKey"`
				AccessSecret string `yaml:"accessSecret"`
				BucketPrefix string `yaml:"bucketPrefix"`
				IamProfile   string `yaml:"iamProfile"`
			} `yaml:"objectStorage"`
			Redis struct {
				Password string `yaml:"password"`
			} `yaml:"redis"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"gitlab"`
		GitlabRunner struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"gitlabRunner"`
		Nexus struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			LicenseKey string `yaml:"license_key"`
			Ingress    struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Sso struct {
				Enabled bool `yaml:"enabled"`
				IdpData struct {
					EntityID    string `yaml:"entityId"`
					Username    string `yaml:"username"`
					FirstName   string `yaml:"firstName"`
					LastName    string `yaml:"lastName"`
					Email       string `yaml:"email"`
					Groups      string `yaml:"groups"`
					IdpMetadata string `yaml:"idpMetadata"`
				} `yaml:"idp_data"`
				Role []struct {
					ID          string        `yaml:"id"`
					Name        string        `yaml:"name"`
					Description string        `yaml:"description"`
					Privileges  []interface{} `yaml:"privileges"`
					Roles       []interface{} `yaml:"roles"`
				} `yaml:"role"`
			} `yaml:"sso"`
			Flux struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"nexus"`
		Sonarqube struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Sso struct {
				Enabled      bool   `yaml:"enabled"`
				ClientID     string `yaml:"client_id"`
				ProviderName string `yaml:"provider_name"`
				Certificate  string `yaml:"certificate"`
				Login        string `yaml:"login"`
				Name         string `yaml:"name"`
				Email        string `yaml:"email"`
				Group        string `yaml:"group"`
			} `yaml:"sso"`
			Database struct {
				Host     string `yaml:"host"`
				Port     int    `yaml:"port"`
				Database string `yaml:"database"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			} `yaml:"database"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"sonarqube"`
		Haproxy struct {
			Git struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"haproxy"`
		Anchore struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
				Upgrade struct {
					DisableWait bool `yaml:"disableWait"`
				} `yaml:"upgrade"`
			} `yaml:"flux"`
			AdminPassword string `yaml:"adminPassword"`
			Enterprise    struct {
				Enabled     bool   `yaml:"enabled"`
				LicenseYaml string `yaml:"licenseYaml"`
			} `yaml:"enterprise"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Sso struct {
				Enabled       bool   `yaml:"enabled"`
				ClientID      string `yaml:"client_id"`
				RoleAttribute string `yaml:"role_attribute"`
			} `yaml:"sso"`
			Database struct {
				Host          string `yaml:"host"`
				Port          string `yaml:"port"`
				Username      string `yaml:"username"`
				Password      string `yaml:"password"`
				Database      string `yaml:"database"`
				FeedsDatabase string `yaml:"feeds_database"`
			} `yaml:"database"`
			Redis struct {
				Host     string `yaml:"host"`
				Port     string `yaml:"port"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			} `yaml:"redis"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"anchore"`
		Mattermostoperator struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"mattermostoperator"`
		Mattermost struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Enterprise struct {
				Enabled bool   `yaml:"enabled"`
				License string `yaml:"license"`
			} `yaml:"enterprise"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Sso struct {
				Enabled         bool   `yaml:"enabled"`
				ClientID        string `yaml:"client_id"`
				ClientSecret    string `yaml:"client_secret"`
				AuthEndpoint    string `yaml:"auth_endpoint"`
				TokenEndpoint   string `yaml:"token_endpoint"`
				UserAPIEndpoint string `yaml:"user_api_endpoint"`
			} `yaml:"sso"`
			Database struct {
				Host     string `yaml:"host"`
				Port     string `yaml:"port"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
				Database string `yaml:"database"`
				SslMode  string `yaml:"ssl_mode"`
			} `yaml:"database"`
			ObjectStorage struct {
				Endpoint     string `yaml:"endpoint"`
				AccessKey    string `yaml:"accessKey"`
				AccessSecret string `yaml:"accessSecret"`
				Bucket       string `yaml:"bucket"`
			} `yaml:"objectStorage"`
			Elasticsearch struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"elasticsearch"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"mattermost"`
		Velero struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Plugins []interface{} `yaml:"plugins"`
			Values  struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"velero"`
		Keycloak struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Database struct {
				Host     string `yaml:"host"`
				Type     string `yaml:"type"`
				Port     int    `yaml:"port"`
				Database string `yaml:"database"`
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			} `yaml:"database"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
				Key     string `yaml:"key"`
				Cert    string `yaml:"cert"`
			} `yaml:"ingress"`
			Values struct {
			} `yaml:"values"`
		} `yaml:"keycloak"`
		Vault struct {
			Enabled bool `yaml:"enabled"`
			Git     struct {
				Repo string `yaml:"repo"`
				Path string `yaml:"path"`
				Tag  string `yaml:"tag"`
			} `yaml:"git"`
			Flux struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
			} `yaml:"ingress"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"vault"`
	} `yaml:"addons"`
}

func GetAllBigBangSubchartOscalComponentDocuments() ([]oscal.OscalComponentDocument, error) {
	var components []oscal.OscalComponentDocument
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

func getBigBangValues() (BigBangValues, error) {
	var bbValues BigBangValues
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
