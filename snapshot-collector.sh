#!/bin/bash

get_latest_release() {
  releasePlan=$1
  latestRelease=$(
    oc get releases --sort-by=.metadata.creationTimestamp --selector=pac.test.appstudio.openshift.io/event-type=push |
      grep "Succeeded" |
      awk '$3 == "'"${releasePlan}"'"; { print $1 }' |
      tail -1
    )
  if [ -n "${latestRelease}" ]; then
    echo "Latest Release: $latestRelease"
    latestSnapshot=$(oc get release $latestRelease -o yaml | yq '.spec.snapshot')
    if [ -n "${latestSnapshot}" ]; then
        echo "Latest Snapshot: $latestSnapshot"
        oc get snapshot $latestSnapshot -o yaml > latest-snapshot.yaml
    else
      echo "No snapshot found for the latest release."
    fi    
  else
    echo "No release found."
  fi
}

install_oc() {
  CLI_DESTINATION_DIR="${CLI_DESTINATION_DIR:=/usr/local/bin}"

  if ! which oc > /dev/null; then
    echo "Installing oc and kubectl CLIs to ${CLI_DESTINATION_DIR}..."
    mkdir clis-unpacked
    curl -kLo oc.tar.gz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/openshift-client-linux.tar.gz
    tar -xzf oc.tar.gz -C clis-unpacked
    chmod 755 ./clis-unpacked/oc
    chmod 755 ./clis-unpacked/kubectl
    mv ./clis-unpacked/oc "${CLI_DESTINATION_DIR}/oc"
    mv ./clis-unpacked/kubectl "${CLI_DESTINATION_DIR}/kubectl"
    rm -rf ./clis-unpacked
    rm -f oc.tar.gz
  fi
}

set_kube_env() {
  saToken=$1
  oc login --token=$saToken --server=https://api.stone-prd-rh01.pg1f.p1.openshiftapps.com:6443
  kubectl config set-context --current --namespace=crt-redhat-acm-tenant
}

releasePlan=$1
saToken=$2

# Check if the release plan is provided
if [ -z "$releasePlan" ]; then
  echo "Error: release-plan argument is missing."
  exit 1
fi

# Call the function with the release-plan passed into script
install_oc
set_kube_env $saToken
get_latest_release $releasePlan
