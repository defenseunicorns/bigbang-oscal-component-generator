package bigbangoscal

import (
	"fmt"
	"time"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/bigbang"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

func BuildBigBangOscalDocument() (string, error) {
	var (
		backMatterResources = []types.Resources{}
		components          = []types.DefinedComponent{}
		rfc3339Time         = time.Now().Format(time.RFC3339)
	)

	documents, version, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments()
	if err != nil {
		return "", err
	}

	// Collect the components and back-matter fields from Big Bang package component definitions
	for _, doc := range documents {
		components = append(components, doc.ComponentDefinition.Components...)
		backMatterResources = append(backMatterResources, doc.ComponentDefinition.BackMatter.Resources...)
	}

	// Populate the Big Bang OSCAL component definition
	bigBangOscalDocument := types.OscalComponentDocument{
		ComponentDefinition: types.ComponentDefinition{
			UUID:       generateUUID(),
			Components: components,
			BackMatter: types.BackMatter{
				Resources: backMatterResources,
			},
			Metadata: types.Metadata{
				Title:        "Big Bang",
				Version:      version,
				OscalVersion: "1.0.4",
				LastModified: rfc3339Time,
				Parties: []types.Party{
					{
						UUID: generateUUID(),
						Type: "organization",
						Name: "Platform One",
						Links: []types.Link{
							{
								Href: "<https://p1.dso.mil>",
								Rel:  "website",
							},
						},
					},
				},
			},
		},
	}

	yamlDocBytes, err := yaml.Marshal(bigBangOscalDocument)
	if err != nil {
		return "", err
	}
	return string(yamlDocBytes), nil
}

// generateUUID generates UUIDs
func generateUUID() string {
	id := uuid.New()
	idString := fmt.Sprintf("%v", id)

	return idString
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
