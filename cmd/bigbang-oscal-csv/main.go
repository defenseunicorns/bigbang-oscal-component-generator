package main

import (
	"fmt"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/bigbang"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/oscal"
	"gopkg.in/yaml.v2"
	"log"
)

func main() {
	yamlDoc, err := buildCsvDocument()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(yamlDoc)
}

func buildCsvDocument() (string, error) {
	var bigBangOscalDocument oscal.OscalComponentDocument
	var components []oscal.OscalComponent
	documents, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments()
	if err != nil {
		return "", err
	}
	for _, doc := range documents {
		components = append(components, doc.ComponentDefinition.Components...)
	}
	bigBangOscalDocument.ComponentDefinition.Components = components
	yamlDocBytes, err := yaml.Marshal(bigBangOscalDocument)
	if err != nil {
		return "", err
	}
	return string(yamlDocBytes), nil
}
