package main

import (
	"fmt"
	"github.com/defenseunicorns/bigbang-oscal-component-generator/pkg/bigbangoscal"
	"log"
)

func main() {
	yamlDoc, err := bigbangoscal.BuildBigBangOscalDocument()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(yamlDoc)
}
