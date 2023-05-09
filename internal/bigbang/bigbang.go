package bigbang

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/oscal"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v2"
)

// GetAllBigBangSubchartOscalComponentDocuments parses the Big Bang chart's values.yaml file (in the master branch) to
// find all subchart git references, collects all the oscal-component.yaml files, and returns them in an array
func GetAllBigBangSubchartOscalComponentDocuments(chartPath string) ([]types.OscalComponentDocument, string, error) {
	var documents []types.OscalComponentDocument
	bigBangValues, version, err := getBigBangValues(chartPath)
	if err != nil {
		return nil, "", err
	}
	gits := getAllSubchartGitSections(bigBangValues)
	for _, git := range gits {
		document, err := oscal.GetOscalComponentDocumentFromRepo(git.Repo, git.Tag)
		if err != nil {
			// Ignore the error since it is happening in cases where the repo doesn't yet have an OSCAL document,
			// but still log it to stderr so this author doesn't feel dirty inside.
			log.Println(fmt.Errorf("No OSCAL document was found for %v:%v", git.Repo, git.Tag))
		} else {
			log.Println(fmt.Errorf("Validiating OSCAL document: %v:%v", git.Repo, git.Tag))
			valid, _ := validateOscalSchema(document)
			if valid {
				log.Println(fmt.Errorf("Valid OSCAL document was found for %v:%v", git.Repo, git.Tag))
			}

			documents = append(documents, document)
		}
	}

	return documents, version, nil
}

func getBigBangValues(chartPath string) (types.BigBangValues, string, error) {
	var bbValues types.BigBangValues
	version := ""

	if strings.HasPrefix(chartPath, "https") {
		uri, err := url.Parse(chartPath + "/values.yaml")
		if err != nil {
			return bbValues, version, err
		}
		_, bytes, err := http.FetchFromHTTPResource(uri)
		if err != nil {
			return bbValues, version, err
		}
		err = yaml.Unmarshal(bytes, &bbValues)

		uri, err = url.Parse(chartPath + "/Chart.yaml")
		if err != nil {
			return bbValues, version, err
		}
		_, bytes, err = http.FetchFromHTTPResource(uri)
		if err != nil {
			return bbValues, version, err
		}

		metadata := make(map[string]string)
		yaml.Unmarshal(bytes, &metadata)
		version := metadata["version"]

		return bbValues, version, err
	}

	// assume local file
	bytes, err := os.ReadFile(chartPath + "/values.yaml")
	if err != nil {
		return bbValues, version, err
	}
	err = yaml.Unmarshal(bytes, &bbValues)
	if err != nil {
		return bbValues, version, err
	}

	//Get Chart Version

	bytes, err = os.ReadFile(chartPath + "/Chart.yaml")
	if err != nil {
		return bbValues, version, err
	}
	metadata := make(map[string]string)
	yaml.Unmarshal(bytes, &metadata)
	version = metadata["version"]

	return bbValues, version, nil
}

// getAllSubchartGitSections extracts the `git:` section from each subchart of Big Bang and returns them in a slice.
// It uses recursion to also get all the subcharts in the `addons:` section as well. The input is weakly typed because
// we are using reflection for this, but the input does need to be of type `types.BigBangValues` for this to work.
func getAllSubchartGitSections(bigBangValues interface{}) []types.Git {
	var gits []types.Git
	var addons interface{}
	v := reflect.ValueOf(bigBangValues)
	n := reflect.TypeOf(bigBangValues)
	values := make([]interface{}, v.NumField())
	for i := range values {
		reflectValue := v.Field(i)
		name := n.Field(i).Name
		// Recurse on nested addons
		if name == "Addons" {
			addons = reflectValue.Interface()
			gits = append(gits, getAllSubchartGitSections(addons)...)
		}
		if reflectValue.Kind() == reflect.Struct {
			git, ok := convertReflectToGit(reflectValue)
			if ok {
				gits = append(gits, git)
			}
		}
	}

	return gits
}

// convertReflectToGit tries to convert an object of weakly typed `reflect.Value` to strongly typed `types.Git`.
// Returns the resultant object and `true` if it worked, or an empty object and `false` if it fails.
func convertReflectToGit(reflectValue reflect.Value) (types.Git, bool) {
	reflectValueInterface := reflectValue.Interface()
	// Types and Name
	subTypes := reflect.TypeOf(reflectValueInterface)
	// Reflect Value
	subValues := reflect.ValueOf(reflectValueInterface)
	// Validate git field exists
	fbn, ok := subTypes.FieldByName("Git")
	if ok {
		subVal := subValues.FieldByName(fbn.Name)
		gitInterface := subVal.Interface()
		// Try to cast
		gitStruct, ok := gitInterface.(types.Git)
		// Validate cast successful and return types.Git struct
		if ok {
			return gitStruct, true
		}
	}
	// Fall through failure case.
	return types.Git{}, false
}

func validateOscalSchema(document types.OscalComponentDocument) (bool, error) {

	documentJsonb, err := json.Marshal(document)
	if err != nil {
		return false, err
	}

	schemaLoader := gojsonschema.NewReferenceLoader("https://repo1.dso.mil/big-bang/pipeline-templates/pipeline-templates/-/raw/master/oscal/oscal_component_schema.json")
	documentLoader := gojsonschema.NewStringLoader(string(documentJsonb))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)

	if err != nil {
		return false, nil
	}

	if result.Valid() {
		return true, nil
	}

	for _, desc := range result.Errors() {
		log.Println(fmt.Errorf("schema validation failed: %s", desc))
	}

	return false, nil
}
