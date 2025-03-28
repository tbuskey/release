#!/bin/bash

set -o nounset
set -o errexit
set -o pipefail

# save the exit code for junit xml file generated in step gather-must-gather
# pre configuration steps before running installation, exit code 100 if failed,
# save to install-pre-config-status.txt
# post check steps after cluster installation, exit code 101 if failed,
# save to install-post-check-status.txt
EXIT_CODE=100
trap 'if [[ "$?" == 0 ]]; then EXIT_CODE=0; fi; echo "${EXIT_CODE}" > "${SHARED_DIR}/install-pre-config-status.txt"' EXIT TERM

if [[ ${ENABLE_SHARED_VPC} == "yes" ]]; then
  echo "Using shared account"
  export AWS_SHARED_CREDENTIALS_FILE="${CLUSTER_PROFILE_DIR}/.awscred_shared_account"
else
  export AWS_SHARED_CREDENTIALS_FILE="${CLUSTER_PROFILE_DIR}/.awscred"
fi

REGION=${REGION:-$LEASED_RESOURCE}

private_subnet_ids=$(yq-go r -j ${SHARED_DIR}/private_subnet_ids | jq -r '[ . | join(" ") ] | @csv' | sed "s/\"//g")
public_subnet_ids=$(yq-go r -j ${SHARED_DIR}/public_subnet_ids | jq -r '[ . | join(" ") ] | @csv' | sed "s/\"//g")

if [[ -z $private_subnet_ids ]] || [[ -z $public_subnet_ids ]]; then
  echo "Error: Can not get public subnets or private subnets, exit"
  echo "private_subnet_ids: $private_subnet_ids, public_subnet_ids: $public_subnet_ids"
  exit 1
fi

echo "Adding tags for private subnets:$private_subnet_ids, tags: kubernetes.io/role/internal-elb, value is empty."
aws --region $REGION ec2 create-tags --resources $private_subnet_ids --tags Key=kubernetes.io/role/internal-elb,Value=

echo "Adding tags for public subnets:$public_subnet_ids, tags: kubernetes.io/role/elb, value is empty."
aws --region $REGION ec2 create-tags --resources $public_subnet_ids --tags Key=kubernetes.io/role/elb,Value=
