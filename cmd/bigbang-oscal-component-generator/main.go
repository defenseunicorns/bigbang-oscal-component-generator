package main

import (
	"fmt"
	"log"

	"github.com/defenseunicorns/bigbang-oscal-component-generator/pkg/bigbangoscal"
)

func main() {
	yamlDoc, err := bigbangoscal.BuildBigBangOscalDocument()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(yamlDoc)
}
