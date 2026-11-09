# NAIS API reconcilers

This repository contains the reconcilers for the NAIS API.

The main purpose is to create team resources, permissions and maintain them.

## Local development

[nais/api](https://github.com/nais/api) is a dependency for this project, and you will need to
have [mise](https://mise.jdx.dev/) installed
on your system.

To run the reconciler locally, you need to have the nais/api project cloned and running.
See the [nais/api README](https://github.com/nais/api?tab=readme-ov-file#local-development) for more information.

Given that a lot of the reconcilers are using external services, most of these requires authentication and access to
these services.
So ensure that you configure and provide a proper environment for the reconcilers to run.
You may use the example configuration file to skip the boring process of figuring it out:

```shell
mise install         # Install required dependencies
cp .env.example .env # Copy the example configuration file
```

To run the reconciler locally, you can use the following command:

```shell
mise run local
```

This will build the reconciler and run it locally.
It sets an environment variable to communicate with the nais/api project running locally.

### Tests and checks

Run `mise run test` to run the tests with the race detector.

Run `mise run check:golangci-lint` to lint the Go code. The tool version is pinned
in `mise/config.toml` and installed by `mise install`. This check is also included
in `mise run check` and the CI workflow for pull requests and pushes to `main`.

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

Failed team reconciliations and deletions are retried in the background with exponential backoff.
Workers continue processing other teams while retries are delayed. A successful attempt resets the backoff.
New events supersede pending retries and reset backoff when their attempt starts.
Each failure replaces the retry deadline, and success cancels it.
Team request metadata is released once no active, pending, or delayed work remains.
The retry queue is in memory; the regular 30-minute full sync reschedules teams after a restart.

All state and data is stored in NAIS api, and the communication with the API is done through GRPC.

### Grafana legacy notification policies

Reconciliation preserves legacy team policies with their own contact points and
adds the new team/environment policies alongside them. Existing policy order,
matchers, receivers, timing settings and `continue` values are not changed.
Policies referencing reserved `team-` contact points or the reconciler's fallback
mute timing remain subject to the existing ownership and drift checks.

Each reconciliation logs a warning identifying the team, legacy receiver,
zero-based top-level policy index and `continue` value. Remove the legacy policy only after
verifying delivery through the new routes. Earlier policies with `continue=false`
can prevent the new routes from matching; enabling `continue` can result in
duplicate notifications. Reconciliation does not change `continue` automatically.
These compatibility rules do not relax the stricter team-deletion checks below.

### Grafana team deletion

Deleting a team removes its reconciled Grafana folder and all folder contents,
including dashboards, alert rules and subfolders. This is destructive: resources
are not exported or archived. The folder is deleted before its notification
policies so remaining rules are not left running without their routing.

Cleanup runs regardless of alerting feature flags or pilot membership. It removes
only top-level policies matching either the reconciler's generated team parent
with environment routes and final always-muted fallback, or its older flat format
with exact `team` and `env` matchers and no child routes. Both formats must have
the expected receivers, grouping and timing settings. Namespace and folder
matchers do not establish policy ownership. Manual or modified policies matching
the team, including nested or broad team matchers, block cleanup before any
resource is deleted and require manual review.

Unreferenced reconciler-named `team-<slug>-<environment>` contact points are removed,
then the Grafana team is deleted. Legacy contact points are retained, and shared
contact points are retained with warnings for manual review. Already-deleted
resources are tolerated so partial cleanup can be retried.
