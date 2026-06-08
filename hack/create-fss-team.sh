#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail

usage() {
    echo "Usage: $0 -t <team-slug> [-a <entra-group-id>] [-s <slack-channel>] [-c <kubectl-context>]"
    echo ""
    echo "  -t  Team slug (required)"
    echo "  -a  Entra ID / Azure AD group UUID (optional)"
    echo "  -s  Slack alerts channel (optional)"
    echo "  -c  kubectl context (optional)"
    exit 1
}

TEAM_SLUG=""
ENTRA_GROUP_ID=""
SLACK_CHANNEL=""
KUBECTL_CONTEXT=""

while getopts "t:a:s:c:" opt; do
    case $opt in
        t) TEAM_SLUG="$OPTARG" ;;
        a) ENTRA_GROUP_ID="$OPTARG" ;;
        s) SLACK_CHANNEL="$OPTARG" ;;
        c) KUBECTL_CONTEXT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$TEAM_SLUG" ]]; then
    usage
fi

KUBECTL="kubectl"
if [[ -n "$KUBECTL_CONTEXT" ]]; then
    KUBECTL="kubectl --context=$KUBECTL_CONTEXT"
fi

echo "Creating resources for team: $TEAM_SLUG"

# Namespace
$KUBECTL apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $TEAM_SLUG
  labels:
    team: "$TEAM_SLUG"
    nais.io/type: workload
    google-cloud-project: ""
  annotations:
    cnrm.cloud.google.com/project-id: ""
    replicator.nais.io/slackAlertsChannel: "$SLACK_CHANNEL"
EOF

# ServiceAccount
$KUBECTL apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: serviceuser-$TEAM_SLUG
  namespace: $TEAM_SLUG
EOF

# RoleBinding: ServiceAccount -> nais:developer
$KUBECTL apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: serviceuser-$TEAM_SLUG-naisdeveloper
  namespace: $TEAM_SLUG
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nais:developer
subjects:
  - kind: ServiceAccount
    name: serviceuser-$TEAM_SLUG
    namespace: $TEAM_SLUG
EOF

# Build subjects list for team rolebinding
SUBJECTS=""
if [[ -n "$ENTRA_GROUP_ID" ]]; then
    SUBJECTS="- apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: \"$ENTRA_GROUP_ID\""
fi

# RoleBinding: Google Group (+ optional Entra) -> nais:developer
$KUBECTL apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-$TEAM_SLUG-naisdeveloper
  namespace: $TEAM_SLUG
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nais:developer
subjects:
  $SUBJECTS
EOF

# ResourceQuota
$KUBECTL apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: nais-quota
  namespace: $TEAM_SLUG
spec:
  hard:
    pods: "200"
EOF

echo "Done! All resources created for team: $TEAM_SLUG"
