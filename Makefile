SHELL := bash

.PHONY: all
all: clean build generate-file

.PHONY: help
help: ## Show this help message.
	@grep -E '^[a-zA-Z_/-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "; printf "\nUsage:\n"}; {printf "  %-15s %s\n", $$1, $$2}'
	@echo

.PHONY: clean
clean: ## Remove generated artifacts.
	go clean
	rm -rf ./bin/bb-oscal

.PHONY: build
build: ## Build the project.
	CGO_ENABLED=0 go build -o ./bin/bb-oscal ./cmd/bigbang-oscal-component-generator

.PHONY: generate-file
generate-file: ## Generate Big Bang OSCAL component definition and write to 'oscal-component.yaml' file
	cd bin/ && ./bb-oscal > ../oscal-component.yaml

.PHONY: generate-stdout
generate-stdout: clean build ## Generate Big Bang OSCAL component definition and print to stdout
	cd bin/ && ./bb-oscal
