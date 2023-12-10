#!/bin/sh -e
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

# some examples of tox-profile usage

export PYTHONPATH=/mnt/o/var/local/src/toxygen_wrapper.git
TOX_HOME=$HOME/.config/tox
NMAP_CMD='sudo -u debian-tor nmap'

echo INFO: check the download json file
python3 tox_profile.py --command nodes --nodes check \
	$TOX_HOME/DHTnodes.json.new \
	2>&1 | tee /tmp/DHTnodes.json.log

echo INFO: get the tcp nodes/ports from the downloaded json file
python3 tox_profile.py --command nodes --nodes select_tcp \
	--output /tmp/DHTnodes.json.tcp \
	$TOX_HOME/DHTnodes.json.new

echo INFO: run ping/nmap on the tcp nodes/ports from the downloaded json file
python3 tox_profile.py --command nodes --nodes nmap_tcp \
	--nmap_cmd $NMAP_CMD \
	--output /tmp/DHTnodes.json.tcp.out \
	/tmp/DHTnodes.json.tcp
