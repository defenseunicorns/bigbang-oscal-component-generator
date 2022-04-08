package bigbangoscal

import (
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/bigbang"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"gopkg.in/yaml.v2"
)

func BuildBigBangOscalDocument() (string, error) {
	var bigBangOscalDocument types.OscalComponentDocument
	var components []types.OscalComponent
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

//func BuildBigBangComplianceCsv() (string, error) {
//	csvRecords := [][]string{
//		{"implemented-by", "implemented-by-uuid", "uuid", "control-id", "label", "title", "prose", "description"},
//	}
//	var components []oscal.OscalComponent
//	documents, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments()
//	if err != nil {
//		return "", err
//	}
//	for _, doc := range documents {
//		components = append(components, doc.ComponentDefinition.Components...)
//	}
//	nist80053Catalog, err := nist.LoadNist80053Catalog()
//	if err != nil {
//		return "", err
//	}
//	for _, component := range components {
//		implementedBy := component.Title
//		implementedByUuid := component.UUID
//		for _, controlImplementation := range component.ControlImplementations {
//			for _, implementedRequirement := range controlImplementation.ImplementedRequirements {
//				uuid := implementedRequirement.UUID
//				controlId := implementedRequirement.ControlID
//				label :=
//			}
//		}
//	}
//}
