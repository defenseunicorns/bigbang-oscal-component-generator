package bigbang

import (
	"fmt"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/http"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/oscal"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"gopkg.in/yaml.v2"
	"log"
	"net/url"
	"reflect"
)

func GetAllBigBangSubchartOscalComponentDocuments() ([]types.OscalComponentDocument, error) {
	var documents []types.OscalComponentDocument
	bigBangValues, err := getBigBangValues()
	if err != nil {
		return nil, err
	}
	gits := getAllSubchartGitSections(bigBangValues)
	for _, git := range gits {
		document, err := oscal.GetOscalComponentDocumentFromRepo(git.Repo, git.Tag)
		if err != nil {
			// Ignore the error since it is happening in cases where the repo doesn't yet have an OSCAL document,
			// but still log it to stderr so this author doesn't feel dirty inside.
			log.Println(fmt.Errorf("an error occurred when pulling the OSCAL document for %v@%v, the data may or may not have been retrieved: %+v", git.Repo, git.Tag, err))
		}
		documents = append(documents, document)
	}

	return documents, nil
}

func getBigBangValues() (types.BigBangValues, error) {
	var bbValues types.BigBangValues
	fileURL := "https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/values.yaml"
	uri, err := url.Parse(fileURL)
	if err != nil {
		return bbValues, err
	}
	_, bytes, err := http.FetchFromHTTPResource(uri)
	if err != nil {
		return bbValues, err
	}
	err = yaml.Unmarshal(bytes, &bbValues)
	if err != nil {
		return bbValues, err
	}

	return bbValues, nil
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
