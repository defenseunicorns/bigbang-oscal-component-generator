package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/pkg/bigbangoscal"
)

var chartPath string
var oscalPath string

func init() {
	flag.StringVar(&chartPath, "chart", "https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/", "Path to Big Bang Helm chart.  Defaults to master branch on BigBang repo")
	flag.StringVar(&oscalPath, "oscalPath", "oscal-component.yaml", "Path to existing OSCAL file.")
	flag.Parse()
}

func main() {
	yamlDoc, err := bigbangoscal.BuildBigBangOscalDocument(chartPath, oscalPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(yamlDoc)
}
