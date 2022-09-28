#!/usr/bin/env bash
#
# Build docker image with tag based on git revision or tag if it exists
# and push it to the registry. The script is called from .jenkins.yaml.
#
# We also pass on this version string as a --build-arg to the docker
# build so that the resulting binary in the container uses that same
# version string for logs etc.
#
# When modifiying this script run it through shellcheck
# (https://www.shellcheck.net/) before commiting.
#

set -e

script_name=$(basename "$0")

echo "running SUNET/knubbis-fleetlock/$script_name"

# We expect Jenkins to have set GIT_COMMIT for us.
if [ "$GIT_COMMIT" = "" ]; then
    echo "$script_name: GIT_COMMIT is not set, exiting"
    exit 1
fi

VERSION=$(git tag --contains "$GIT_COMMIT" | head -1)
if [ "$VERSION" = "" ]; then
    echo "$script_name: did not find a tag related to revision $GIT_COMMIT, using rev as version"
    VERSION=$GIT_COMMIT
fi

DOCKER_TAG="docker.sunet.se/knubbis/knubbis-fleetlock:$VERSION"
echo "$script_name: building DOCKER_TAG $DOCKER_TAG"

docker build --build-arg "VERSION=$VERSION" --tag "$DOCKER_TAG" .
docker push "$DOCKER_TAG"
