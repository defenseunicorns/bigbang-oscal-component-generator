package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/bigbang"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/internal/types"

	"encoding/csv"
)

func main() {
	var bigBangOscalDocument types.OscalComponentDocument
	var components []types.OscalComponent
	documents, version, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments()
	if err != nil {
		log.Fatal(err)
	}
	for _, doc := range documents {
		components = append(components, doc.ComponentDefinition.Components...)
	}
	bigBangOscalDocument.ComponentDefinition.Components = components
	bigBangOscalDocument.ComponentDefinition.Metadata.Version = version
	bigBangOscalDocument.ComponentDefinition.Metadata.Title = "Big Bang"
	emass := make([][]string, 0)
	for _, component := range components {
		// fmt.Printf("Parsing component: %v\n\n\n", component.Title)
		emass = append(emass, ComponentToEMassRecord(component)...)
	}

	w := csv.NewWriter(os.Stdout)

	for _, record := range emass {
		if err := w.Write(record); err != nil {
			log.Fatalln("Error writing record to csv: %v", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
}

func ControlIDToTitle(id string) string {
	if strings.HasPrefix(id, "ac") {
		return "Access Control"
	}
	if strings.HasPrefix(id, "at") {
		return "Awareness and Training"
	}
	if strings.HasPrefix(id, "au") {
		return "Audit and Accountability"
	}
	if strings.HasPrefix(id, "ca") {
		return "Assessment, Authorization, and Monitoring"
	}
	if strings.HasPrefix(id, "cm") {
		return "Configuration Management"
	}
	if strings.HasPrefix(id, "cp") {
		return "Contingency Planning"
	}
	if strings.HasPrefix(id, "ia") {
		return "Identification and Authentication"
	}
	if strings.HasPrefix(id, "ir") {
		return "Incident Response"
	}
	if strings.HasPrefix(id, "ma") {
		return "Maintenance"
	}
	if strings.HasPrefix(id, "mp") {
		return "Media Protection"
	}
	if strings.HasPrefix(id, "pe") {
		return "Physical Protection"
	}
	if strings.HasPrefix(id, "pl") {
		return "Planning"
	}
	if strings.HasPrefix(id, "pm") {
		return "Program Management"
	}
	if strings.HasPrefix(id, "ps") {
		return "Personnel Security"
	}
	if strings.HasPrefix(id, "pt") {
		return "Personally Identifiable Information Processing and Transparency"
	}
	if strings.HasPrefix(id, "ra") {
		return "Risk Assessment"
	}
	if strings.HasPrefix(id, "sa") {
		return "System and Services Acquisition"
	}
	if strings.HasPrefix(id, "sc") {
		return "System and Communications Protection"
	}
	if strings.HasPrefix(id, "si") {
		return "System and Information Integrity"
	}
	if strings.HasPrefix(id, "sr") {
		return "Supply Chain Risk Management"
	}

	return ""
}

func ComponentToEMassRecord(c types.OscalComponent) [][]string {
	// get the control info later
	records := make([][]string, 0)
	for _, implementation := range c.ControlImplementations[0].ImplementedRequirements {
		implementation.Description = strings.ReplaceAll(implementation.Description, ",", ";")
		implementation.Description = strings.ReplaceAll(implementation.Description, "\n", "  ")
		implementation.Description = strings.ReplaceAll(implementation.Description, "\r", "  ")
		records = append(records, []string{
			implementation.ControlID,                   //ControlId:
			ControlIDToTitle(implementation.ControlID), //ControlTitle
			"",                                //Control Information
			"Non-Compliant",                   //ComplianceStatus:
			"Inherited",                       //ImplementationStatus:
			"Component",                       //CommonControlProvider:
			"Hybrid",                          //SecurityControlDesignation:
			"Examine",                         //TestMethod:
			"",                                //NAJustification:
			"",                                //EstimatedCompletionData:
			implementation.Description,        //ImplementationNarrative:
			"Platform One",                    //ResponsibleEntities:
			"",                                //IM:
			"CRWG Yellow Criticality Control", //Criticality:
			"Constantly",                      //Frequency:
			"Automated",                       //Method:
			"Status of control is captured as OSCAL document provided with BigBang release.  ",                                                                                                                            //Reporting:
			"Any failure to meet this control will be captured as an issue in Big Bang's issue board at https://repo1.dso.mil/platform-one/big-bang/bigbang/-/issues until released in a BigBang version that statisfies", //Tracking:
			fmt.Sprintf("This control is satisfied by using the component %v as part of the BigBang stack", c.Title),                                                                                                      //SLCMComments:
		})
	}
	return records
}

//func buildCsvDocument() (string, error) {
//	var bigBangOscalDocument oscal.OscalComponentDocument
//	var components []oscal.OscalComponent
//	documents, err := bigbang.GetAllBigBangSubchartOscalComponentDocuments()
//	if err != nil {
//		return "", err
//	}
//	for _, doc := range documents {
//		components = append(components, doc.ComponentDefinition.Components...)
//	}
//	bigBangOscalDocument.ComponentDefinition.Components = components
//	yamlDocBytes, err := yaml.Marshal(bigBangOscalDocument)
//	if err != nil {
//		return "", err
//	}
//	return string(yamlDocBytes), nil
//}
