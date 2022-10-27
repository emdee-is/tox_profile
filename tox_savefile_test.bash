#!/bin/sh
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

# tox_savefile.py has a lot of features so it needs test coverage

PREFIX=/mnt/o/var/local/src
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

[ -d $WRAPPER ] || {
    ERROR wrapper is required https://git.plastiras.org/emdee/toxygen_wrapper
    exit 3
}
export  PYTHONPATH=$WRAPPER

json=$HOME/.config/tox/DHTnodes.json
[ -s $json ] || exit 4

which jq > /dev/null && HAVE_JQ=1 || HAVE_JQ=0
which nmap > /dev/null && HAVE_NMAP=1 || HAVE_NMAP=0

sudo rm -f /tmp/toxic_profile.* /tmp/toxic_nodes.*

test_jq () {
    [ $# -eq 3 ] || {
	ERROR test_jq '#' "$@"
	return 3
    }
    in=$1
    out=$2
    err=$3
    [ -s $in ] || {
	ERROR $i test_jq null $in
	return 4
    }
    jq . < $in >$out 2>$err || {
	ERROR $i test_jq $json
	return 5
    }
    grep error: $err && {
	ERROR $i test_jq $json
	return 6
    }
    [ -s $out ] || {
	ERROR $i null $out
	return 7
    }
    [ -s $err ] || rm -f $err
    return 0
}

i=0
[ "$HAVE_JQ" = 0 ] || \
    test_jq $json /tmp/toxic_nodes.json /tmp/toxic_nodes.err || exit ${i}$?
[ -f /tmp/toxic_nodes.json ] || cp -p $json /tmp/toxic_nodes.json
json=/tmp/toxic_nodes.json

i=1
# required password
INFO $i decrypt /tmp/toxic_profile.bin
$EXE $target --command decrypt --output /tmp/toxic_profile.bin $tox || exit ${i}1
[ -s /tmp/toxic_profile.bin ] || exit ${i}2

tox=/tmp/toxic_profile.bin
INFO $i info $tox
$EXE $target --command info --info info $tox 2>/tmp/toxic_profile.info || {
    ERROR $i $EXE $target --command info --info info $tox
    exit ${i}3
}
[ -s /tmp/toxic_profile.info ] || exit ${i}4

INFO $i /tmp/toxic_profile.save
$EXE $target --command info --info save --output /tmp/toxic_profile.save $tox 2>/dev/null || exit ${i}5
[ -s /tmp/toxic_profile.save ] || exit ${i}6

i=2
for the_tox in $tox /tmp/toxic_profile.save ; do
    DBUG $i $the_tox
    the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
    for elt in json yaml pprint repr ; do
	INFO $i $the_base.$elt
	DBUG $EXE $target \
	     --command info --info $elt \
	     --output $the_base.$elt $the_tox '2>'$the_base.$elt.err
	$EXE $target --command info --info $elt \
		    --output $the_base.$elt $the_tox 2>$the_base.$nmap.err || exit ${i}0
       [ -s $the_base.$elt ] || exit ${i}1
    done

    $EXE $target --command edit --edit help $the_tox 2>/dev/null  || exit ${i}2

    # edit the status message
    INFO $i $the_base.Status_message  'STATUSMESSAGE,.,Status_message,Toxxed on Toxic'
    $EXE $target --command edit --edit 'STATUSMESSAGE,.,Status_message,Toxxed on Toxic' \
	       --output $the_base.Status_message.tox $the_tox  2>&1|grep EDIT || exit ${i}3
    [ -s $the_base.Status_message.tox ] || exit ${i}3
    $EXE $target --command info $the_base.Status_message.tox 2>&1|grep Toxxed || exit ${i}4

    # edit the nick_name
    INFO $i $the_base.Nick_name  'NAME,.,Nick_name,FooBar'
    $EXE $target --command edit --edit 'NAME,.,Nick_name,FooBar' \
	       --output $the_base.Nick_name.tox $the_tox  2>&1|grep EDIT || exit ${i}5
    [ -s $the_base.Nick_name.tox ] || exit ${i}5
    $EXE $target --command info $the_base.Nick_name.tox 2>&1|grep FooBar || exit ${i}6

    # set the DHTnodes to empty
    INFO $i $the_base.noDHT  'DHT,.,DHTnode,'
    $EXE $target --command edit --edit 'DHT,.,DHTnode,' \
	       --output $the_base.noDHT.tox $the_tox  2>&1|grep EDIT || exit ${i}7
    [ -s $the_base.noDHT.tox ] || exit ${i}7
    $EXE $target --command info $the_base.noDHT.tox 2>&1|grep 'NO DHT' || exit ${i}8

done

i=3
[ "$HAVE_JQ" = 0 ] || \
for the_json in $json ; do
    DBUG $i $the_json
    the_base=`echo $the_json | sed -e 's/.json$//' -e 's/.tox$//'`
    for nmap in select_tcp select_udp select_version ; do
	$EXE $target --command nodes --nodes $nmap \
	     --output $the_base.$nmap.json $the_json || {
            WARN $i $the_json $nmap ${i}1
            continue
            }
	[ -s $the_base.$nmap.json ] || {
            WARN $i $the_json $nmap ${i}2
            continue
            }
	[ $nmap = select_tcp ] && \
	    grep '"status_tcp": false' $the_base.$nmap.json && {
            WARN $i $the_json $nmap ${i}3
            continue
            }
	[ $nmap = select_udp ] && \
	    grep '"status_udp": false' $the_base.$nmap.json && {
            WARN $i $the_json $nmap ${i}4
            continue
            }
	test_jq $the_base.$nmap.json $the_base.$nmap.json.out /tmp/toxic_nodes.err || {
	    retval=$?
	    WARN $i $the_base.$nmap.json 3$?
	}
	INFO $i $the_base.$nmap
    done
done

ls -l /tmp/toxic_profile.* /tmp/toxic_nodes.*

# DEBUG=0 /usr/local/bin/proxy_ping_test.bash tor || exit 0
ip route | grep ^def || exit 0

i=4
the_tox=$tox
[ "$HAVE_JQ" = 0 ] || \
[ "$HAVE_NMAP" = 0 ] || \
for the_tox in $tox /tmp/toxic_profile.save ; do
    DBUG $i $the_tox
    the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
    for nmap in nmap_tcp nmap_udp nmap_onion ; do
#	[ $nmap = select_tcp ] && continue
#	[ $nmap = select_udp ] && continue
        INFO $i $the_base.$nmap 
        $EXE $target --command info --info $nmap \
	     --output $the_base.$nmap.out $the_tox 2>$the_base.$nmap.err || {
	    # select_tcp may be empty and jq errors
	    # exit ${i}1
	    WARN $i $the_base.$nmap.err
	    continue
	}
	[ -s  $the_base.$nmap.out ] || {
	    ERROR $i $the_base.$nmap.out
	    continue
	}
    done
done

i=5
[ "$HAVE_JQ" = 0 ] || \
for the_json in $json ; do
    DBUG $i $the_json
    the_base=`echo $the_json | sed -e 's/.save$//' -e 's/.json$//'`
    for nmap in nmap_tcp nmap_udp ; do
        INFO $i $the_base.$nmap 
        $EXE $target --command nodes --nodes $nmap \
	     --output $the_base.$nmap $the_json 2>$the_base.$nmap.err || {
            WARN $i $the_json $nmap ${i}1
            continue
            }
	[ -s  $the_base.$nmap ] || {
            ERROR $i $the_json $nmap ${i}2
            exit ${i}2
            }
    done
done

i=6
DBUG $i
$EXE $target --command nodes --nodes download \
             --output /tmp/toxic_nodes.new $json || {
    ERROR $i $EXE $target --command nodes --nodes download $json
    exit ${i}1
}
[ -s /tmp/toxic_nodes.new ] || exit ${i}4
json=/tmp/toxic_nodes.new
[ "$HAVE_JQ" = 0 ] || \
jq . < $json >/tmp/toxic_nodes.new.json 2>>/tmp/toxic_nodes.new.err || {
    ERROR $i jq $json
    exit ${i}2
}
[ "$HAVE_JQ" = 0 ] || \
grep error: /tmp/toxic_nodes.new.err && {
    ERROR $i jq $json
    exit ${i}3
}    

exit 0
