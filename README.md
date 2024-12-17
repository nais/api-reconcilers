# NAIS API reconcilers

This repository contains the reconcilers for the NAIS API.

The main purpose is to create team resources, permissions and maintain them.

## Local development

[nais/api](https://github.com/nais/api) is a dependency for this project.
To run the reconciler locally, you need to have the nais/api project cloned and running.
See the [nais/api README](https://github.com/nais/api?tab=readme-ov-file#local-development) for more information.

Given that a lot of the reconcilers are using external services, most of these requires authentication and access to
these services.
So ensure that you configure and provide a proper environment for the reconcilers to run.
You may use the example configuration file to skip the boring process of figuring it out:

```shell
cp .env.example .env
```

To run the reconciler locally, you can use the following command:

```shell
make local
```

This will build the reconciler and run it locally.
It sets an environment variable to communicate with the nais/api project running locally.

Run `make test` to run the tests.

### Local kind cluster setup (only relevant if doing stuff against Kubernetes, e.g. the namespace reconciler)

1. Ensure you have [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) installed.

2. Create a kind cluster:

```shell
kind create cluster 
```

3. Apply required cluster resources:

```shell
kubectl apply -f ./hack/configconnectorcontexts.yaml
kubectl apply -f ./hack/rbac.yaml
```

4. Create a NAV_ONPREM_CLUSTERS entry in the .env file like so:

Run the following command in the same terminal as the previous step:

```shell
NAV_ONPREM_CLUSTERS="kind-kind|127.0.0.1:$(docker ps | grep kindest | cut -d":" -f3 | cut -d "-" -f1)|$(kubectl create token api-reconciler --duration=99999h)"
(echo ""; echo "NAV_ONPREM_CLUSTERS=\"$NAV_ONPREM_CLUSTERS\"") >> .env # only works once
```

## Architecture

The project contains a set of reconcilers which are run on schedule or triggered by events.
A manager is responsible for running the reconcilers and handling the errors.

The manager will listen for pubsub events and trigger the correct reconcilers when needed.

All state and data is stored in NAIS api, and the communication with the API is done through GRPC.


