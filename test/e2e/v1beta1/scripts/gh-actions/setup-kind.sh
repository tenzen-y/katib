#!/usr/bin/env bash

# Copyright 2022 The Kubeflow Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This shell script is used to setup Katib deployment.

set -o errexit
set -o pipefail
set -o nounset
cd "$(dirname "$0")"

CLUSTER_NAME=${1:-"katib-e2e-cluster"}
DOWNLOADED_BASE_DIR=${2:-"/tmp/images"}
IMAGE_TAG=${3:-"e2e-test"}
REGISTRY="docker.io/kubeflowkatib"

echo "Start to setup KinD Kubernetes Cluster"
kubectl wait --for condition=ready --timeout=5m node "$CLUSTER_NAME-control-plane"
kubectl version
kubectl cluster-info
kubectl get nodes

DOWNLOADED_IMAGES=()
while IFS='' read -r TARBALL
do
  DOWNLOADED_IMAGES+=("$TARBALL")
done < <(find "$DOWNLOADED_BASE_DIR" -name '*.tar')

for IMAGE in "${DOWNLOADED_IMAGES[@]}"
do
  IMAGE_NAME="$REGISTRY/$(basename "$IMAGE" | cut -d. -f1 ):$IMAGE_TAG"
  echo "Load Container Image \"$IMAGE\" as $IMAGE_NAME"
  docker import "$IMAGE" "$IMAGE_NAME"
  kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"

  docker rmi "$IMAGE_NAME"
  rm -rf "$IMAGE"
done

echo 'y' |docker system prune
docker image list --all
