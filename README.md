# bigbang-oscal-component-generator

## ⚠️ Deprecation and Archive Notice

This project is no longer receiving maintenance updates and is being deprecated. Please see [Component-Generator](https://github.com/defenseunicorns/component-generator) as the universal tool for aggregating component definition OSCAL files.

## Usage

This tool was purpose-built for [Big Bang](https://repo1.dso.mil/big-bang/bigbang), so these usage instructions are intended to describe how it can be used in Big Bang's CI system.

To make this tool available as an executable command in Big Bang CI, the binary can be built and installed into the $PATH of the [bb-ci container image](https://repo1.dso.mil/big-bang/pipeline-templates/pipeline-templates/-/blob/master/dockerfiles/bb-ci/Dockerfile) as such:

```Dockerfile
FROM golang:1.19 as build

RUN git clone https://github.com/defenseunicorns/bigbang-oscal-component-generator.git \
    && cd bigbang-oscal-component-generator \
    && make build

FROM <base-image>

COPY --from=build /go/bigbang-oscal-component-generator/bin/bb-oscal /usr/local/bin/bb-oscal
```

Once the binary is installed in the $PATH of the bb-ci container image, it can be used in a pipeline that runs in the [Big Bang](https://repo1.dso.mil/big-bang/bigbang) repository as such:

```bash
bb-oscal --chart chart/
```

The `--chart` flag is used to specify the path to the Big Bang Helm chart. The example above assumes the command is being ran from the root of the Big Bang repository. If the flag is not used, the default behavior is to fetch the [chart from Repo1](https://repo1.dso.mil/platform-one/big-bang/bigbang/-/raw/master/chart/).
