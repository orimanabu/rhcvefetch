#!/bin/bash

if [ x"$#" != x"1" ]; then
	echo "$0 subcmd"
	exit 1
fi
subcmd=$1; shift

logdir=./logs
suffix=$(date '+%Y%m%d-%H%M%S')
mkdir -p ${logdir}

case ${subcmd} in
prepare)
	uv sync
	uv run playwright install chromium
	;;
run)
	logfile=${logdir}/fetch-${suffix}.log
	uv run rhcvefetch > ${logfile} 2>&1
	;;
runpush)
	logfile=${logdir}/fetch-${suffix}.log
	(time uv run rhcvefetch) > ${logfile} 2>&1
	git add data >> ${logfile} 2>&1
	git commit -m "Fetched: ${suffix}" >> ${logfile} 2>&1
	git push >> ${logfile} 2>&1
	;;
*)
	echo "unknown subcmd: ${subcmd}"
	exit 1
	;;
esac
