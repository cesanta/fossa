#!/bin/bash
BASE=$(dirname $0)

SCRATCH=$(mktemp -d -t tmp.XXXXXXXXXX)
function finish {
    rm -rf "${SCRATCH}"
}
trap finish EXIT

mkdir -p ${SCRATCH}/docs/fossa
cp ${BASE}/../docs/index.html ${SCRATCH}/docs/fossa
tar c -C ${SCRATCH} . | ssh -T circleci@cesanta.com
