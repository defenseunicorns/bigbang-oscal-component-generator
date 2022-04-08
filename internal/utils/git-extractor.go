package utils

import (
	"fmt"
	"reflect"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
)

// Extract git objects from bigbang values
func ExtractGit(valuesStruct interface{}) []types.Git {

	var gits []types.Git
	var addons interface{}
	v := reflect.ValueOf(valuesStruct)
	n := reflect.TypeOf(valuesStruct)
	values := make([]interface{}, v.NumField())

	for i := range values {
		reflectValue := v.Field(i)
		name := n.Field(i).Name
		// Recurse on nested addons
		if name == "Addons" {
			addons = reflectValue.Interface()
			gits = append(gits, ExtractGit(addons)...)
		}
		gits = addValidatedGitToSlice(gits, reflectValue)
	}
	return gits
}

// Adds git to slice if its able to extract from reflected value.
func addValidatedGitToSlice(gits []types.Git, reflectValue reflect.Value) []types.Git {
	if reflectValue.Kind() == reflect.Struct {
		git, ok := convertReflectToGit(reflectValue)
		if ok {
			gits = append(gits, git)
		}
	}
	return gits
}

// Retrieves the Git struct from a value in BigBang Chart if it exists.
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

func ExtractTest() {
	x := struct {
		Foo string
		Bar int
	}{"foo", 2}

	v := reflect.ValueOf(x)

	values := make([]interface{}, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		values[i] = v.Field(i).Interface()
	}

	fmt.Println(values)
}
