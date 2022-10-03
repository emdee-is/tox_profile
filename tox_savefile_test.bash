#!/bin/sh
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

PREFIX=/o/var/local/src
EXE=python3.sh
WRAPPER=$PREFIX/toxygen_wrapper

[ -f /usr/local/bin/usr_local_tput.bash ] && \
    . /usr/local/bin/usr_local_tput.bash || {
	DEBUG() { echo DEBUG $* ; }
	INFO() { echo INFO $* ; }
	WARN() { echo WARN $* ; }
	ERROR() { echo ERROR $* ; }
    }

# set -- -e
target=$PREFIX/tox_profile/tox_savefile.py
[ -s $target ] || exit 1

tox=$HOME/.config/tox/toxic_profile.tox
[ -s $tox ] || exit 2

json=$HOME/.config/tox/DHTnodes.json
[ -s $json ] || exit 3

[ -d $WRAPPER ] || { ERROR wrapper is required https://git.plastiras.org/emdee/toxygen_wrapper ; exit 5 ; }
export  PYTHONPATH=$WRAPPER

which jq > /dev/null && HAVE_JQ=1 || HAVE_JQ=0
which nmap > /dev/null && HAVE_NMAP=1 || HAVE_NMAP=0

sudo rm -f /tmp/toxic_profile.* /tmp/toxic_nodes.*

[ "$HAVE_JQ" = 0 ] || \
  jq . <  $json >/tmp/toxic_nodes.json || { ERROR jq $json ; exit 4 ; }
[ -f /tmp/toxic_nodes.json ] || cp -p $json /tmp/toxic_nodes.json
json=/tmp/toxic_nodes.json

# required password
INFO decrypt /tmp/toxic_profile.bin
$EXE $target --command decrypt --output /tmp/toxic_profile.bin $tox || exit 11
[ -s /tmp/toxic_profile.bin ] || exit 12

tox=/tmp/toxic_profile.bin
INFO info $tox
$EXE $target --command info --info info $tox 2>/tmp/toxic_profile.info || {
    ERROR $EXE $target --command info --info info $tox
    exit 13
}
[ -s /tmp/toxic_profile.info ] || exit 14

INFO /tmp/toxic_profile.save
$EXE $target --command info --info save --output /tmp/toxic_profile.save $tox 2>/dev/null || exit 15
[ -s /tmp/toxic_profile.save ] || exit 16

for the_tox in /tmp/toxic_profile.save ; do
    the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
    for elt in json yaml pprint repr ; do
	INFO $the_base.$elt
	[ "$DEBUG" != 1 ] || echo DEBUG $EXE $target \
				  --command info --info $elt \
				  --output $the_base.$elt $the_tox
	$EXE $target --command info --info $elt \
		    --output $the_base.$elt $the_tox 2>/dev/null || exit 20
       [ -s $the_base.$elt ] || exit 21
    done

    $EXE $target --command edit --edit help $the_tox 2>/dev/null  || exit 22

    INFO $the_base.edit1  'STATUSMESSAGE,.,Status_message,Toxxed on Toxic'
    $EXE $target --command edit --edit 'STATUSMESSAGE,.,Status_message,Toxxed on Toxic' \
	       --output $the_base.edit1.tox $the_tox  2>&1|grep EDIT
    [ -s $the_base.edit1.tox ] || exit 23
    $EXE $target --command info $the_base.edit1.tox 2>&1|grep Toxxed || exit 24

    INFO $the_base.edit2  'NAME,.,Nick_name,FooBar'
    $EXE $target --command edit --edit 'NAME,.,Nick_name,FooBar' \
	       --output $the_base.edit2.tox $the_tox  2>&1|grep EDIT
    [ -s $the_base.edit2.tox ] || exit 25
    $EXE $target --command info $the_base.edit2.tox 2>&1|grep FooBar || exit 26

done

the_tox=$json
the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.json$//'`
[ "$HAVE_JQ" = 0 ] || \
    for nmap in select_tcp select_udp select_version ; do
	INFO $the_base.$nmap
	$EXE $target --command nodes --nodes $nmap \
	     --output $the_base.$nmap.json $the_tox || exit 31
	[ -s $the_base.$nmap.json ] || exit 32
	[ $nmap = select_tcp ] && \
	    grep '"status_tcp": false' $the_base.select_tcp.json && exit 33
	[ $nmap = select_udp ] && \
	    grep '"status_udp": false' $the_base.select_udp.json && exit 34
    done


ls -l /tmp/toxic_profile.* /tmp/toxic_nodes.*

/usr/local/bin/proxy_ping_test.bash tor || exit 0

the_tox=$tox
the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
[ "$HAVE_JQ" = 0 ] || \
[ "$HAVE_NMAP" = 0 ] || \
    for nmap in nmap_tcp nmap_udp nmap_onion ; do
#	[ $nmap = select_tcp ] && continue
#	[ $nmap = select_udp ] && continue
        INFO $the_base.$nmap 
        $EXE $target --command info --info $nmap \
	     --output $the_base.$nmap $the_tox.json || {
	    # select_tcp may be empty and jq errors
	    # exit 41
	    WARN  $the_base.$nmap.json
	    continue
	}
	[ -s  $the_base.$nmap.json ] || exit 41
    done

the_json=$json
the_base=`echo $json | sed -e 's/.save$//' -e 's/.json$//'`
[ "$HAVE_JQ" = 0 ] || \
    for nmap in nmap_tcp nmap_udp ; do
        INFO $the_base.$nmap 
        $EXE $target --command nodes --nodes $nmap \
	     --output $the_base.$nmap.json $the_json  || exit 51
	[ -s  $the_base.$nmap.json ] || exit 52
    done

exit 0

