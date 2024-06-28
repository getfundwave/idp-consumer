#!/usr/bin/env bash

version=$1
GITLAB_TOKEN=${2:-}

[[ -n $version ]] || { echo "usage: bash publish.sh <version> <optional GITLAB_TOKEN>" && exit 1; }

mv ../.npmrc ../.npmrc.cp

npm ci
npm publish --tag $version --access public

if [[ -n $GITLAB_TOKEN ]]; then


echo @fundwave:registry=https://gitlab.com/api/v4/projects/24877554/packages/npm/ >> ./.npmrc
echo //gitlab.com/api/v4/projects/24877554/packages/npm/:_authToken="$GITLAB_TOKEN" >> ./.npmrc
npm publish --tag $version
rm ./.npmrc

fi

mv ../.npmrc.cp ../.npmrc
