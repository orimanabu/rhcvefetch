#!/bin/bash

logdir=./logs
suffix=$(date '+%Y%m%d-%H%M%S')
mkdir -p ${logdir}

uv run rhcvefetch > ${logdir}/fetch-${suffix}.log 2>&1
git add data
git commit -m "Fetched: ${suffix}"
