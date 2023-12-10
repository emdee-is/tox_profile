#!/bin/sh
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

# tox_profile.py has a lot of features so it needs test coverage

PREFIX=/mnt/o/var/local
ROLE=text
DEBUG=1
EXE=/var/local/bin/python3.bash
WRAPPER$PREFIX/src/toxygen_wrapper.git
tox=$HOME/.config/tox/toxic_profile.tox
[ -s $tox ] || exit 2
target$PREFIX/src/tox_profile/tox_profile.py

OUT=/tmp/toxic_profile

ps ax | grep -q tor && netstat -n4le | grep -q :9050
[ $? -eq 0 ] && HAVE_TOR=1 || HAVE_TOR=0

[ -f /usr/local/bin/usr_local_tput.bash ] && \
    . /usr/local/bin/usr_local_tput.bash || {
	DBUG() { echo DEBUG $* ; }
	INFO() { echo INFO $* ; }
	WARN() { echo WARN $* ; }
	ERROR() { echo ERROR $* ; }
    }

if [ -z "$TOXCORE_LIBS" ] &&  [ ! -d libs ] ; then
    mkdir libs
    cd libs
    # /lib/x86_64-linux-gnu/libtoxcore.so.2
    for pro in qtox toxic ; do
	if which $pro 2> /dev/null ; then
	    DBUG linking to $pro libtoxcore
 	    lib=$( ldd `which $pro` | grep libtoxcore|sed -e 's/.* => //' -e 's/ .*//')
	    [ -n "$lib" -a -f "$lib" ] || { WARN $Lib ; continue ; }
	    INFO linking to $lib
	    for elt in libtoxcore.so libtoxav.so libtoxencryptsave.so ; do
		ln -s "$lib" "$elt"
	    done
	    export TOXCORE_LIBS=$PWD
	    break
	fi
    done
    cd ..
elif [ -z "$TOXCORE_LIBS" ] &&  [ -d libs ] ; then
    export TOXCORE_LIBS=$PWD/libs
fi


# set -- -e
[ -s $target ] || exit 1

[ -d $WRAPPER ] || {
    ERROR wrapper is required https://git.plastiras.org/emdee/toxygen_wrapper
    exit 3
}
export  PYTHONPATH=$WRAPPER

json=$HOME/.config/tox/DHTnodes.json
[ -s $json ] || exit 4

which jq > /dev/null && HAVE_JQ=1 || HAVE_JQ=0
which nmap > /dev/null && HAVE_NMAP=1 || HAVE_NMAP=0

sudo rm -f $OUT.* /tmp/toxic_nodes.*

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
    test_jq $json /tmp/toxic_nodes.json /tmp/toxic_nodes.err || {
	ERROR test_jq failed on $json
	exit ${i}$?
	}
[ -f /tmp/toxic_nodes.json ] || cp -p $json /tmp/toxic_nodes.json
json=/tmp/toxic_nodes.json

i=1
# required password
INFO $i decrypt $OUT.bin
$EXE $target --command decrypt --output $OUT.bin $tox || exit ${i}1
[ -s $OUT.bin ] || exit ${i}2

tox=$OUT.bin
INFO $i info $tox
$EXE $target --command info --info info $tox 2>$OUT.info || {
    ERROR $i $EXE $target --command info --info info $tox
    exit ${i}3
}
[ -s $OUT.info ] || exit ${i}4

INFO $i $EXE $target --command info --info save --output $OUT.save $tox
$EXE $target --command info --info save --output $OUT.save $tox 2>/dev/null ||  {
    ERROR $?
    exit ${i}5
}

[ -s $OUT.save ] || exit ${i}6

i=2
[ $# -ne 0 -a $1 -ne $i ] || \
! INFO $i Info and editing || \
for the_tox in $tox $OUT.save ; do
    DBUG $i $the_tox
    the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
    for elt in json yaml pprint repr ; do
	if [ $elt = yaml -o $elt = json ] ; then
	    # ModuleNotFoundError
	    python3 -c "import $elt" 2>/dev/null || continue
	fi
	INFO $i $the_base.$elt
	DBUG $EXE $target \
	     --command info --info $elt \
	     --output $the_base.$elt $the_tox '2>'$the_base.$elt.err
	$EXE $target --command info --info $elt \
	     --output $the_base.$elt $the_tox 2>$the_base.$elt.err || {
	    tail $the_base.$elt.err
	    if [ $elt != yaml -a $elt != json ] ; then
		exit ${i}0
	    else
		WARN $elt
	    fi
	}
	[ -s $the_base.$elt ] || {
	    WARN no output  $the_base.$elt
#	    exit ${i}1
	}
    done

    DBUG     $EXE $target --command edit --edit help $the_tox
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
    $EXE $target --command info $the_base.noDHT.tox 2>&1 | grep 'NO DHT' || exit ${i}8

done

i=3
[ "$#" -ne 0 -a "$1" != "$i" ] || \
[ "$HAVE_JQ" = 0 ] || \
! INFO $i Nodes || \
for the_json in $json ; do
    DBUG $i $the_json
    the_base=`echo $the_json | sed -e 's/.json$//' -e 's/.tox$//'`
    for nmap in clean check select_tcp select_udp select_version; do
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

i=4
[ $# -ne 0 -a "$1" -ne $i ] || \
[ "$HAVE_TOR" = 0 ] || \
[ ! -f /etc/tor/torrc ] || \
! INFO $i Onions || \
for the_tox in /etc/tor/torrc ; do
    DBUG $i $the_tox
    the_base=`echo $OUT.save | sed -e 's/.save$//' -e 's/.tox$//'`
    #  exits
    for slot in config test; do
        if [ $slot = exits ] && ! netstat -nle4 | grep -q :9050 ; then
           WARN Tor not running
           continue
        fi
        INFO $target --command onions --onions $slot \
             --output $the_base.$slot.out $the_tox
        DBUG=1 $EXE $target --command onions --onions $slot \
             --log_level 10 \
             --output $the_base.$slot.out $the_tox|| {
             WARN $i $?
             continue
        }
	[ true -o -s $the_base.$slot.out ] || {
	    WARN $i empty $the_base.$slot.out
	    continue
	}
      done
  done

# ls -l $OUT.* /tmp/toxic_nodes.*

# DEBUG=0 /usr/local/bin/proxy_ping_test.bash tor || exit 0
ip route | grep ^def || exit 0

i=5
the_tox=$tox
[ $# -ne 0 -a "$1" != "$i" ] || \
[ "$HAVE_JQ" = 0 ] || \
[ "$HAVE_NMAP" = 0 ] || \
! INFO $i Making dogfood || \
for the_tox in $tox $OUT.save ; do
    DBUG $i $the_tox
    the_base=`echo $the_tox | sed -e 's/.save$//' -e 's/.tox$//'`
    for nmap in nmap_relay nmap_dht nmap_path ; do
#	[ $nmap = select_tcp ] && continue
	if [ $nmap = nmap_dht ] && [ $HAVE_TOR = 1 ] ; then
	    INFO skipping $nmap because HAVE_TOR
	    continue
	fi
        INFO $i $the_base.$nmap
	DBUG $target --command info --info $nmap \
	     --output $the_base.$nmap.out $the_tox
        $EXE $target --command info --info $nmap \
	     --output $the_base.$nmap.out $the_tox 2>$the_base.$nmap.err || {
	    # select_tcp may be empty and jq errors
	    # exit ${i}1
	    WARN $i $? $the_base.$nmap.err
	    tail $the_base.$nmap.err
	    continue
	}
	[ -s $the_base.$nmap.out ] || {
	    WARN $i empty $the_base.$nmap.out
	    continue
	}
    done
done

i=6
[ $# -ne 0 -a "$1" != "$i" ] || \
[ "$HAVE_JQ" = 0 ] || \
! INFO $i Eating dogfood || \
for the_json in $json ; do
    DBUG $i $the_json
    the_base=`echo $the_json | sed -e 's/.save$//' -e 's/.json$//'`
    for nmap in nmap_tcp nmap_udp ; do
	if [ $nmap = nmap_udp ] && [ $HAVE_TOR = 1 ] ; then
	    INFO skipping $nmap because HAVE_TOR
	    continue
	fi
        INFO $i $target --command nodes --nodes $nmap --output $the_base.$nmap
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

i=7
DBUG $i
$EXE $target --command nodes --nodes download \
     --output /tmp/toxic_nodes.new $json || {
	ERROR $i $EXE $target --command nodes --nodes download $json
	exit ${i}1
}
[ -s /tmp/toxic_nodes.new ] || exit ${i}4
INFO $i  downloaded  /tmp/toxic_nodes.new
json=/tmp/toxic_nodes.new
[ $# -ne 0 -a "$1" != "$i" ] || \
	[ "$HAVE_JQ" = 0 ] || \
	jq . < $json >/tmp/toxic_nodes.new.json 2>>/tmp/toxic_nodes.new.json.err || {
	    ERROR $i jq $json
	    exit ${i}2
	}
INFO $i  jq from /tmp/toxic_nodes.new.json

[ $# -ne 0 -a "$1" != "$i" ] || \
	[ "$HAVE_JQ" = 0 ] || \
	grep error: /tmp/toxic_nodes.new.json.err && {
	    ERROR $i jq $json
	    exit ${i}3
	}
INFO $i  no errors in  /tmp/toxic_nodes.new.err


exit 0
