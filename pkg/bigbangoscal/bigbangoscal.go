package bigbangoscal

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/bigbang"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

func BuildBigBangOscalDocument(chartPath string, oscalPath string) (string, error) {
	var (
		backMatterResources = []types.Resources{}
		components          = []types.DefinedComponent{}
		rfc3339Time         = time.Now().Format(time.RFC3339)
		partyUUID           = generateUUID()
	)

	existingDoc := types.OscalComponentDocument{}

	log.Println(fmt.Errorf("Reading %s", oscalPath))

	if oscalPath != "" {
		log.Println(fmt.Errorf("Reading %s", oscalPath))
		readOscal(oscalPath, &existingDoc)

		log.Println(fmt.Errorf("Detected %d parties", len(existingDoc.ComponentDefinition.Metadata.Parties)))

		if len(existingDoc.ComponentDefinition.Metadata.Parties) > 0 {
			log.Println(fmt.Errorf("Using existing UUID %s", partyUUID))
			partyUUID = existingDoc.ComponentDefinition.Metadata.Parties[0].UUID
		}
	}

	documents, version, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments(chartPath)
	if err != nil {
		return "", err
	}

	// Collect the components and back-matter fields from Big Bang package component definitions
	for _, doc := range documents {
		attachVersionProps(&doc)

		components = append(components, doc.ComponentDefinition.Components...)

		backMatterResources = append(backMatterResources, doc.ComponentDefinition.BackMatter.Resources...)
	}

	// childCompare := reflect.DeepEqual(components, existingDoc.ComponentDefinition.Components)
	// diff := deep.Equal(components, existingDoc.ComponentDefinition.Components)

	// if diff != nil {
	// 	log.Println(fmt.Errorf("compare failed: %v", diff))
	// }

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
						UUID: partyUUID,
						Type: "organization",
						Name: "Platform One",
						Links: []types.Link{
							{
								Href: "https://p1.dso.mil",
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

func readOscal(path string, doc *types.OscalComponentDocument) *types.OscalComponentDocument {
	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, doc)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return doc
}

func attachVersionProps(doc *types.OscalComponentDocument) error {
	for i := range doc.ComponentDefinition.Components {
		doc.ComponentDefinition.Components[i].Props = append(doc.ComponentDefinition.Components[i].Props, types.Property{
			Name:  "version",
			Value: doc.ComponentDefinition.UUID,
		})
	}

	return nil
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
