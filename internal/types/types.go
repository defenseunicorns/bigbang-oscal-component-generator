package types

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
		JwksURI              string `yaml:"jwks_uri"`
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
		Enabled         bool `yaml:"enabled"`
		Git             Git  `yaml:"git"`
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
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"istiooperator"`
	Jaeger struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
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
		Git     Git  `yaml:"git"`
		Flux    struct {
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
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"clusterAuditor"`
	Gatekeeper struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
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
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kyverno"`
	Kyvernopolicies struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kyvernopolicies"`
	Kyvernoreporter struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"kyvernoreporter"`
	Logging struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
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
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
	} `yaml:"eckoperator"`
	Fluentbit struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"fluentbit"`
	Promtail struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"promtail"`
	Loki struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Strategy      string `yaml:"strategy"`
		ObjectStorage struct {
			Endpoint     string `yaml:"endpoint"`
			Region       string `yaml:"region"`
			AccessKey    string `yaml:"accessKey"`
			AccessSecret string `yaml:"accessSecret"`
			BucketNames  struct {
			} `yaml:"bucketNames"`
		} `yaml:"objectStorage"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"loki"`
	Neuvector struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Flux struct {
		} `yaml:"flux"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"neuvector"`
	Tempo struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Flux struct {
		} `yaml:"flux"`
		Sso struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ClientSecret string `yaml:"client_secret"`
		} `yaml:"sso"`
		ObjectStorage struct {
			Endpoint     string `yaml:"endpoint"`
			Region       string `yaml:"region"`
			AccessKey    string `yaml:"accessKey"`
			AccessSecret string `yaml:"accessSecret"`
			Bucket       string `yaml:"bucket"`
			Insecure     bool   `yaml:"insecure"`
		} `yaml:"objectStorage"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"tempo"`
	Monitoring struct {
		Enabled bool `yaml:"enabled"`
		Git     Git  `yaml:"git"`
		Flux    struct {
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
		Git     Git  `yaml:"git"`
		Flux    struct {
		} `yaml:"flux"`
		Ingress struct {
			Gateway string `yaml:"gateway"`
		} `yaml:"ingress"`
		Sso struct {
			Enabled      bool   `yaml:"enabled"`
			ClientID     string `yaml:"client_id"`
			ProviderName string `yaml:"provider_name"`
			ProviderType string `yaml:"provider_type"`
			IssuerURI    string `yaml:"issuer_uri"`
			IdpURL       string `yaml:"idp_url"`
			ConsoleURL   string `yaml:"console_url"`
			Groups       string `yaml:"groups"`
			Cert         string `yaml:"cert"`
		} `yaml:"sso"`
		Values struct {
		} `yaml:"values"`
		PostRenderers []interface{} `yaml:"postRenderers"`
	} `yaml:"twistlock"`
	Addons struct {
		Argocd struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
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
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
			Chains        struct {
			} `yaml:"chains"`
		} `yaml:"authservice"`
		MinioOperator struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"minioOperator"`
		Minio struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
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
			Git  Git `yaml:"git"`
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
			SMTP struct {
				Password string `yaml:"password"`
			} `yaml:"smtp"`
			Redis struct {
				Password string `yaml:"password"`
			} `yaml:"redis"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"gitlab"`
		GitlabRunner struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"gitlabRunner"`
		Nexus struct {
			Enabled    bool   `yaml:"enabled"`
			Git        Git    `yaml:"git"`
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
			Git     Git  `yaml:"git"`
			Flux    struct {
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
			Git  Git `yaml:"git"`
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
			Git     Git  `yaml:"git"`
			Flux    struct {
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
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"mattermostoperator"`
		Mattermost struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
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
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Plugins []interface{} `yaml:"plugins"`
			Values  struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"velero"`
		Keycloak struct {
			Enabled  bool `yaml:"enabled"`
			Git      Git  `yaml:"git"`
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
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"keycloak"`
		Vault struct {
			Enabled bool `yaml:"enabled"`
			Git     Git  `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Ingress struct {
				Gateway string `yaml:"gateway"`
				Key     string `yaml:"key"`
				Cert    string `yaml:"cert"`
			} `yaml:"ingress"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"vault"`
		MetricsServer struct {
			Enabled string `yaml:"enabled"`
			Git     Git    `yaml:"git"`
			Flux    struct {
			} `yaml:"flux"`
			Values struct {
			} `yaml:"values"`
			PostRenderers []interface{} `yaml:"postRenderers"`
		} `yaml:"metricsServer"`
	} `yaml:"addons"`
}
type Git struct {
	Repo string `yaml:"repo"`
	Path string `yaml:"path,omitempty"`
	Tag  string `yaml:"tag,omitempty"`
}

type OscalComponentDocument struct {
	ComponentDefinition struct {
		UUID     string `yaml:"uuid"`
		Metadata struct {
			Title        string `yaml:"title"`
			LastModified string `yaml:"last-modified"`
			Version      string `yaml:"version"`
			OscalVersion string `yaml:"oscal-version"`
			Parties      struct {
				UUID  string `yaml:"uuid"`
				Type  string `yaml:"type"`
				Name  string `yaml:"name"`
				Links struct {
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
		RoleID     string   `yaml:"role-id"`
		PartyUUIDS []string `yaml:"party-uuids"`
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
