package main

import (
	"fmt"

	internalYaml "github.com/defenseunicorns/bigbang-oscal-component-generator/internal/yaml"
)

func main() {
	s, _ := internalYaml.BuildBigBangOscalComponentDocument()
	fmt.Println(s)
}
