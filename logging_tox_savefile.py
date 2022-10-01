# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

"""
Reads a tox profile and prints out information on what's in there to stderr.

Call it with one argument, the filename of the profile for the decrypt or info
commands, or the filename of the nodes file for the nodes command.

3 commands are supported:
--command decrypt 
  decrypts the profile and writes to the result to stdout

--command info
  prints info about what's in the Tox profile to stderr

--command nodes
  assumes you are reading a json nodes file instead of a profile
"""

"""
  --output Destination for info/decrypt - defaults to stdout
  --info default='info',
         choices=['info', 'repr', 'yaml','json', 'pprint']
         with --info=info prints info about the profile to stderr
  --indent default=2
         indents the output as: 'yaml','json', 'pprint' 

  --output Destination for the command - required
  --nodes 
       choices=['select_tcp', 'select_udp', 'nmap_tcp', 'select_version', 'nmap_udp']
       select_udp      - select udp nodes
       select_tcp      - select tcp nodes
       nmap_tcp        - test tcp nodes with namp
       select_version  - select nodes that are the latest version
       download        - download nodes from --download_nodes_url
  --download_nodes_url https://nodes.tox.chat/json

"""

# originally from:
# https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in

import sys
import os
import struct
from socket import inet_ntop, AF_INET6, AF_INET
import logging
import argparse
from pprint import pprint
import shutil

try:
    # https://pypi.org/project/msgpack/
    import msgpack
except ImportError as e:
    msgpack = None
try:
    import yaml
except ImportError as e:
    yaml = None
try:
    import json
except ImportError as e:
    json = None
try:
    # https://pypi.org/project/coloredlogs/
    import coloredlogs
    if 'COLOREDLOGS_LEVEL_STYLES' not in os.environ:
        os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
except ImportError as e:
    coloredlogs = False
try:
    # https://git.plastiras.org/emdee/toxygen_wrapper
    from wrapper.toxencryptsave import ToxEncryptSave
except ImportError as e:
    print(f"Import Error {e}")
    print("Download toxygen_wrapper to deal with encrypted tox files, from:")
    print("https://git.plastiras.org/emdee/toxygen_wrapper")
    print("Just put the parent of the wrapper directory on your PYTHONPATH")
    print("You also need to link your libtoxcore.so and libtoxav.so")
    print("and libtoxencryptsave.so into wrapper/../libs/")
    print("Link all 3 from libtoxcore.so if you have only libtoxcore.so")
    ToxEncryptSave = None
try:
    from wrapper_tests.support_http import download_url
except:
    try:
        from support_http import download_url
    except ImportError as e:
        print(f"Import Error {e}")
        print("Download toxygen_wrapper to deal with encrypted tox files, from:")
        print("https://git.plastiras.org/emdee/toxygen_wrapper")
        download_url = None
    
LOG = logging.getLogger('TSF')
bUSE_NMAP = True
sDIR = os.environ.get('TMPDIR', '/tmp')
# nodes
sTOX_VERSION = "1000002018"
bHAVE_JQ = shutil.which('jq')

#messenger.c
MESSENGER_STATE_TYPE_NOSPAMKEYS = 1
MESSENGER_STATE_TYPE_DHT = 2
MESSENGER_STATE_TYPE_FRIENDS = 3
MESSENGER_STATE_TYPE_NAME = 4
MESSENGER_STATE_TYPE_STATUSMESSAGE = 5
MESSENGER_STATE_TYPE_STATUS = 6
MESSENGER_STATE_TYPE_GROUPS = 7
MESSENGER_STATE_TYPE_TCP_RELAY = 10
MESSENGER_STATE_TYPE_PATH_NODE = 11
MESSENGER_STATE_TYPE_CONFERENCES = 20
MESSENGER_STATE_TYPE_END = 255
dSTATE_TYPE = {
    MESSENGER_STATE_TYPE_NOSPAMKEYS: "NOSPAMKEYS",
    MESSENGER_STATE_TYPE_DHT: "DHT",
    MESSENGER_STATE_TYPE_FRIENDS: "FRIENDS",
    MESSENGER_STATE_TYPE_NAME: "NAME",
    MESSENGER_STATE_TYPE_STATUSMESSAGE: "STATUSMESSAGE",
    MESSENGER_STATE_TYPE_STATUS: "STATUS",
    MESSENGER_STATE_TYPE_GROUPS: "GROUPS",
    MESSENGER_STATE_TYPE_TCP_RELAY: "TCP_RELAY",
    MESSENGER_STATE_TYPE_PATH_NODE: "PATH_NODE",
    MESSENGER_STATE_TYPE_CONFERENCES: "CONFERENCES",
    MESSENGER_STATE_TYPE_END: "END",
}

def decrypt_data(data):
    from getpass import getpass

    if not ToxEncryptSave: return data

    oToxES = ToxEncryptSave()
    if not oToxES.is_data_encrypted(data):
        LOG.debug('Not encrypted')
        return data
    assert data[:8] == b'toxEsave', data[:8]

    sys.stdout.flush()
    password = getpass('Password: ')
    assert password
    newData = oToxES.pass_decrypt(data, password)
    LOG.debug('Decrypted: ' +str(len(newData)) +' bytes')
    return newData

def str_to_hex(raw_id, length=None):
    if length is None: length = len(raw_id)
    res = ''.join('{:02x}'.format(ord(raw_id[i])) for i in range(length))
    return res.upper()

def bin_to_hex(raw_id, length=None):
    if length is None: length = len(raw_id)
    res = ''.join('{:02x}'.format(raw_id[i]) for i in range(length))
    return res.upper()

def lProcessFriends(state, index, length, result):
    """Friend:

The integers in this structure are stored in Big Endian format.

Length  Contents
1  uint8_t Status
32  Long term public key
1024  Friend request message as a byte string
1  PADDING
2  uint16_t Size of the friend request message
128  Name as a byte string
2  uint16_t Size of the name
1007  Status message as a byte string
1  PADDING
2  uint16_t Size of the status message
1  uint8_t User status (see also: USERSTATUS)
3  PADDING
4  uint32_t Nospam (only used for sending a friend request)
8  uint64_t Last seen time

"""
    dStatus = { #  Status  Meaning
               0:  'Not a friend',
               1:  'Friend added',
               2: 'Friend request sent',
               3: 'Confirmed friend',
               4: 'Friend online'
               }
    slen = 1+32+1024+1+2+128+2+1007+1+2+1+3+4+8 # 2216
    assert length % slen == 0
    lIN = []
    for i in range(length // slen):
        delta = i*slen
        status = struct.unpack_from(">b", result, delta)[0]
        o = delta+1; l = 32
        pk = bin_to_hex(result[o:o+l], l)

        o = delta+1+32+1024+1+2+128; l = 2
        nsize = struct.unpack_from(">H", result, o)[0]
        o = delta+1+32+1024+1+2; l = 128
        name = str(result[o:o+nsize], 'utf-8')

        o = delta+1+32+1024+1+2+128+2+1007; l = 2
        msize = struct.unpack_from(">H", result, o)[0]
        o = delta+1+32+1024+1+2+128+2; l = 1007
        mame = str(result[o:o+msize], 'utf-8')
        LOG.info(f"Friend #{i}  {dStatus[status]} {name} {pk}")
        lIN += [{"Status": dStatus[status],
                 "Name": name,
                 "Pk": pk}]
    return lIN

def lProcessGroups(state, index, length, result):
    lIN = []
    i = 0
    if not msgpack:
        LOG.debug(f"TODO process_chunk Groups = no msgpack bytes={length}")
        return []
    try:
        groups = msgpack.loads(result, raw=True)
        LOG.debug(f"TODO process_chunk Groups len={len(groups)}")
        for group in groups:
            assert len(group) == 7, group
            i += 1
            state_values, \
            state_bin, \
            topic_info, \
            mod_list, \
            keys, \
            self_info, \
            saved_peers, = group

            assert len(state_values) == 8, state_values
            manually_disconnected, \
            group_name_len, \
            privacy_state, \
            maxpeers, \
            password_length, \
            version, \
            topic_lock, \
            voice_state = state_values
            LOG.info(f"lProcessGroups #{i} version={version}")
            dBINS = {"Version": version}
            lIN += [{"State_values": dBINS}]

            assert len(state_bin) == 5, state_bin
            shared_state_sig, \
            founder_public_key, \
            group_name_len, \
            password_length, \
            mod_list_hash = state_bin
            LOG.info(f"lProcessGroups #{i} founder_public_key={bin_to_hex(founder_public_key)}")
            dBINS = {"Founder_public_key": bin_to_hex(founder_public_key)}
            lIN += [{"State_bin": dBINS}]

            assert len(topic_info) == 6, topic_info
            topic_info_topic = str(topic_info[3], 'utf-8')
            LOG.info(f"lProcessGroups #{i} topic_info_topic={topic_info_topic}")
            dBINS = {"topic_info_topic": topic_info_topic}
            lIN += [{"Topic_info": dBINS}]

            assert len(mod_list) == 2, mod_list
            num_moderators = mod_list[0]
            LOG.debug(f"lProcessGroups #{i} num moderators={mod_list[0]}")
            #define CRYPTO_SIGN_PUBLIC_KEY_SIZE    32
            mods = mod_list[1]
            assert len(mods) % 32 == 0, len(mods)
            assert len(mods) == num_moderators * 32, len(mods)
            lMODS = []
            for j in range(num_moderators):
                mod = mods[j*32:j*32 + 32]
                LOG.info(f"lProcessGroups group#{i} mod#{j} sig_pk={bin_to_hex(mod)}")
                lMODS += [{"Sig_pk": bin_to_hex(mod)}]
            if lMODS: lIN += [{"Moderators": lMODS}]

            assert len(keys) == 4, keys
            LOG.debug(f"lProcessGroups #{i} {repr(list(map(len, keys)))}")
            chat_public_key, \
                chat_secret_key, \
                self_public_key, \
                self_secret_key = keys
            LOG.info(f"lProcessGroups #{i} chat_public_key={bin_to_hex(chat_public_key)}")
            lIN[0].update({"Chat_public_key": bin_to_hex(chat_public_key)})
            if int(bin_to_hex(chat_secret_key), 16) != 0:
                # 192 * b'0'
                LOG.info(f"lProcessGroups #{i} chat_secret_key={bin_to_hex(chat_secret_key)}")
                lIN[0].update({"Chat_secret_key": bin_to_hex(chat_secret_key)})

            LOG.info(f"lProcessGroups #{i} self_public_key={bin_to_hex(self_public_key)}")
            lIN[0].update({"Self_public_key": bin_to_hex(self_public_key)})
            LOG.info(f"lProcessGroups #{i} self_secret_key={bin_to_hex(self_secret_key)}")
            lIN[0].update({"Self_secret_key": bin_to_hex(self_secret_key)})

            assert len(self_info) == 4, self_info
            self_nick_len, self_role, self_status, self_nick = self_info
            self_nick = str(self_nick, 'utf-8')
            LOG.info(f"lProcessGroups #{i} self_nick={self_nick}")
            dBINS = {"Self_nick": self_nick}
            lIN += [{"Self_info": dBINS}]

            assert len(saved_peers) == 2, saved_peers

    except Exception as e:
        LOG.warn(f"process_chunk Groups #{i} error={e}")
    return lIN

def lProcessTcpRelay(state, index, length, result):
    """Node Info (packed node format)

The Node Info data structure contains a Transport Protocol, a Socket
    Address, and a Public Key. This is sufficient information to start
    communicating with that node. The binary representation of a Node Info is
    called the “packed node format”.

  Length  Type  Contents
    1 bit  Transport Protocol  UDP = 0, TCP = 1
    7 bit  Address Family  2 = IPv4, 10 = IPv6
    4 | 16  IP address  4 bytes for IPv4, 16 bytes for IPv6
    2  Port Number  Port number
    32  Public Key  Node ID

"""
    delta = 0
    relay = 0
    lIN = []
    while length > 0:
        status = struct.unpack_from(">B", result, delta)[0]
        if status >= 128:
            ipv = 'TCP'
            af = status - 128
        else:
            ipv = 'UDP'
            af = status
        if af == 2:
            af = 'IPv4'
            alen = 4
            ipaddr = inet_ntop(AF_INET, result[delta+1:delta+1+alen])
        else:
            af = 'IPv6'
            alen = 16
            ipaddr = inet_ntop(AF_INET6, result[delta+1:delta+1+alen])
            total = 1 + alen + 2 + 32
            port = int(struct.unpack_from(">H", result, delta+1+alen)[0])
            pk = bin_to_hex(result[delta+1+alen+2:delta+1+alen+2+32], 32)
            LOG.info(f"DHTnode #{relay} bytes={length} status={status} ip={ipv} af={af} ip={ipaddr} port={port} pk={pk}")
            lIN += [{"Bytes": length,
                     "Status": status,
                     "Ip": ipv,
                     "Af": af,
                     "Ip": ipaddr,
                     "Port": port,
                     "Pk": pk}]
        if bUSE_NMAP:
            cmd = f"nmap -Pn -n -sT -p T:{port} {ipaddr}"

        delta += total
        length -= total
        relay += 1
    return lIN

def lProcessDHTnodes(state, index, length, result):
    relay = 0
    status = struct.unpack_from("<L", result, 0)[0]
    # 4  uint32_t (0x159000D)
    assert status == 0x159000D
    length -= 4
    delta = 4
    lIN = []
    while length > 0:
        slen = struct.unpack_from("<L", result, delta)[0]
        stype = struct.unpack_from("<H", result, delta+4)[0]
        smark = struct.unpack_from("<H", result, delta+6)[0]
        assert smark == 0x11CE
        total = slen + 4 + 2 + 2
        subtotal = 0
        offset = delta
        while offset < slen: #loop over nodes
            status = struct.unpack_from(">B", result, offset+8)[0]
            assert status < 12
            ipv = 'UDP'
            if status == 2:
                af = 'IPv4'
                alen = 4
                ipaddr = inet_ntop(AF_INET, result[offset+8+1:offset+8+1+alen])
            else:
                af = 'IPv6'
                alen = 16
                ipaddr = inet_ntop(AF_INET6, result[offset+8+1:offset+8+1+alen])
            subtotal = 1 + alen + 2 + 32
            port = int(struct.unpack_from(">H", result, offset+8+1+alen)[0])
            pk = bin_to_hex(result[offset+8+1+alen+2:offset+8+1+alen+2+32], 32)

            LOG.info(f"DHTnode #{relay} status={status} ipaddr={ipaddr} port={port} {pk}")
            lIN += [{"status": status,
                     "ipaddr": ipaddr,
                     "port": port,
                     "pk": pk}]
            if bUSE_NMAP:
                cmd = f"nmap -Pn -n -sU -p U:{port} {ipaddr}"
            offset += subtotal
        delta += total
        length -= total
        relay += 1
    return lIN

def process_chunk(index, state):
    global lOUT, bOUT, iTOTAL

    length = struct.unpack_from("<H", state, index)[0]
    data_type = struct.unpack_from("<H", state, index + 4)[0]
    new_index = index + length + 8
    result = state[index + 8:index + 8 + length]
    iTOTAL += length + 8
    
    # plan on repacking as we read - this is just a starting point
    # We'll add the results back to bOUT to see if we get what we started with.
    # Then will will be able to selectively null sections.
    bOUT += struct.pack("<H", length) + struct.pack("<H", data_type) + result
    
    if data_type == MESSENGER_STATE_TYPE_NOSPAMKEYS:
        nospam = bin_to_hex(result[0:4])
        public_key = bin_to_hex(result[4:36])
        private_key = bin_to_hex(result[36:68])
        LOG.info(f"nospam = {nospam}")
        LOG.info(f"public_key = {public_key}")
        LOG.info(f"private_key = {private_key}")
        aIN = {"Nospam": f"{nospam}",
               "Public_key": f"{public_key}",
               "Private_key": f"{private_key}"}
        lOUT += [{"Nospam_keys": aIN}]

    elif data_type == MESSENGER_STATE_TYPE_DHT:
        LOG.debug(f"process_chunk {dSTATE_TYPE[data_type]} length={length}")
        lIN = lProcessDHTnodes(state, index, length, result)
        if lIN: lOUT += [{"DHT_nodes": lIN}]

    elif data_type == MESSENGER_STATE_TYPE_FRIENDS:
        LOG.debug(f"TODO process_chunk {length // 2216} FRIENDS {length} {length % 2216}")
        lIN = lProcessFriends(state, index, length, result)
        if lIN: lOUT += [{"Friends": lIN}]

    elif data_type == MESSENGER_STATE_TYPE_NAME:
        name = str(state[index + 8:index + 8 + length], 'utf-8')
        LOG.info("Nick_name = " +name)
        aIN = {"Nick_name": name}
        lOUT += [{"Nick_name": aIN}]

    elif data_type == MESSENGER_STATE_TYPE_STATUSMESSAGE:
        mess = str(state[index + 8:index + 8 + length], 'utf-8')
        LOG.info(f"StatusMessage = " +mess)
        aIN = {"Status_message": mess}
        lOUT += [{"Status_message": aIN}]

    elif data_type == MESSENGER_STATE_TYPE_STATUS:
        # 1  uint8_t status (0 = online, 1 = away, 2 = busy)
        dStatus = {0: 'online', 1: 'away', 2: 'busy'}
        status = struct.unpack_from(">b", state, index)[0]
        status = dStatus[status]
        LOG.info(f"{dSTATE_TYPE[data_type]} = " +status)
        aIN = {f"Online_status": status}
        lOUT += [{"Online_status": aIN}]

    elif data_type == MESSENGER_STATE_TYPE_GROUPS:
        lIN = lProcessGroups(state, index, length, result)
        if lIN: lOUT += [{"Groups": lIN}]

    elif data_type == MESSENGER_STATE_TYPE_TCP_RELAY:
        lIN = lProcessTcpRelay(state, index, length, result)
        if lIN: lOUT += [{"Tcp_relays": lIN}]

    elif data_type == MESSENGER_STATE_TYPE_PATH_NODE:
        LOG.debug(f"TODO process_chunk {dSTATE_TYPE[data_type]} bytes={length}")
        
    elif data_type == MESSENGER_STATE_TYPE_CONFERENCES:
        if length > 0:
            LOG.debug(f"TODO process_chunk {dSTATE_TYPE[data_type]} bytes={length}")
        else:
            LOG.info(f"NO {dSTATE_TYPE[data_type]}")
            lOUT += [{"Conferences": []}]

    elif data_type != MESSENGER_STATE_TYPE_END:
        LOG.warn("UNRECOGNIZED datatype={datatype}")
        
    else:
        LOG.info("END") # That's all folks...
        return
        
    # failsafe
    if index + 8 >= len(state): return
    process_chunk(new_index, state)

def bAreWeConnected(): 
    # FixMe: Linux
    sFile = f"/proc/{os.getpid()}/net/route"
    if not os.path.isfile(sFile): return None
    i = 0
    for elt in open(sFile, "r").readlines():
        if elt.startswith('Iface'): continue
        if elt.startswith('lo'): continue
        i += 1
    return i > 0

sNMAP_TCP = """#!/bin/bash
ip=""
declare -a ports
jq '.|with_entries(select(.key|match("nodes"))).nodes[]|select(.status_tcp)|select(.ipv4|match("."))|.ipv4,.tcp_ports' | while read line ; do
    if [ -z "$ip" ] ; then
	ip=`echo $line|sed -e 's/"//g'`
	ports=()
	continue
    elif [ "$line" = '[' ] ; then
	continue
    elif [ "$line" = ']' ] ; then
	if ! route | grep -q ^def ; then
            echo ERROR no route
            exit 3
        fi
	if [ "$ip" = '"NONE"' -o  "$ip" = 'NONE' ] ; then
	    :
	elif ping -c 1 $ip | grep '100% packet loss' ; then
	    echo WARN failed ping $ip
	else
	    echo INFO $ip "${ports[*]}"
	    cmd="nmap -Pn -n -sT -p T:"`echo "${ports[*]}" |sed -e 's/ /,/g'`
	    dbug $cmd $ip
	    $cmd $ip | grep /tcp
	fi
	ip=""
	continue
    else
	port=`echo $line|sed -e 's/,//'`
	ports+=($port)
	#	echo '>>' $ip "${ports[*]}"
    fi
done"""

def vBashFileNmapTcp():
    f = "NmapTcp.bash"
    sFile = os.path.join(sDIR, f)
    if not os.path.exists(sFile):
        with open(sFile, 'wt') as iFd:
            iFd.write(sNMAP_TCP)
        os.chmod(sFile, 0o0775)
    return sFile

def vBashFileNmapUdp():
    f = "NmapUdp.bash"
    sFile = os.path.join(sDIR, f)
    if not os.path.exists(sFile):
        with open(sFile, 'wt') as iFd:
            iFd.write(sNMAP_TCP.
                      replace('nmap -Pn -n -sT -p T',
                              'nmap -Pn -n -sU -p U').
                      replace('tcp_ports','udp_ports').
                      replace('status_tcp','status_udp'))
        os.chmod(sFile, 0o0775)
    return sFile

def vSetupLogging(loglevel=logging.DEBUG):
    global LOG
    if coloredlogs:
        aKw = dict(level=loglevel,
                   logger=LOG,
                   fmt='%(name)s %(levelname)s %(message)s')
        coloredlogs.install(**aKw)
    else:
        aKw = dict(level=loglevel,
                   format='%(name)s %(levelname)-4s %(message)s')
        logging.basicConfig(**aKw)

    logging._defaultFormatter = logging.Formatter(datefmt='%m-%d %H:%M:%S')
    logging._defaultFormatter.default_time_format = '%m-%d %H:%M:%S'
    logging._defaultFormatter.default_msec_format = ''

def oMainArgparser(_=None):
    if not os.path.exists('/proc/sys/net/ipv6'):
        bIpV6 = 'False'
    else:
        bIpV6 = 'True'
    lIpV6Choices=[bIpV6, 'False']

    parser = argparse.ArgumentParser(epilog=__doc__)
    # list(dSTATE_TYPE.values())
    # ['nospamkeys', 'dht', 'friends', 'name', 'statusmessage', 'status', 'groups', 'tcp_relay', 'path_node', 'conferences']
    
    parser.add_argument('--output', type=str, default='',
                        help='Destination for info/decrypt - defaults to stderr')
    parser.add_argument('--command', type=str, default='info',
                        choices=['info', 'decrypt', 'nodes'],
                        # required=True,
                        help='Action command - default: info')
    parser.add_argument('--indent', type=int, default=2,
                        help='Indent for yaml/json/pprint')
    parser.add_argument('--info', type=str, default='info',
                        choices=['info', 'repr', 'yaml','json', 'pprint'],
                        help='Format for info command')
    choices = []
    if bHAVE_JQ:
        choices += ['select_tcp', 'select_udp', 'select_version', 'nmap_tcp', 'nmap_udp']
    if download_url:
        choices += ['download']
    parser.add_argument('--nodes', type=str, default='',
                        choices=choices,
                        help='Action for nodes command (requires jq)')
    parser.add_argument('--download_nodes_url', type=str,
                        default='https://nodes.tox.chat/json')
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='tox profile file - may be encrypted')
    return parser

if __name__ == '__main__':
    iTOTAL = 0
    lArgv = sys.argv[1:]
    parser = oMainArgparser()
    oArgs = parser.parse_args(lArgv)

    sFile = oArgs.profile
    assert os.path.isfile(sFile), sFile

    vSetupLogging()

    bSAVE = open(sFile, 'rb').read()
    if ToxEncryptSave and bSAVE[:8] == b'toxEsave':
        try:
            bSAVE = decrypt_data(bSAVE)
        except Exception as e:
            LOG.error(f"decrypting {sFile} - {e}")
            sys.exit(1)
    assert bSAVE

    oStream = None
    if oArgs.command == 'decrypt':
        if oArgs.output:
            oStream = open(oArgs.output, 'rb')
        else:
            oStream = sys.stdout
        oStream.write(bSAVE)
        
    elif oArgs.command == 'nodes':
        iRet = -1
        if oArgs.nodes == 'select_tcp':
            assert oArgs.output, "--output required for this command"
            assert bHAVE_JQ, "jq is required for this command"
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_tcp)|select(.ipv4|match(\".\"))' "
            iRet = os.system(cmd +f" > {oArgs.output}")

        elif oArgs.nodes == 'select_udp':
            assert oArgs.output, "--output required for this command"
            assert bHAVE_JQ, "jq is required for this command"
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_udp)|select(.ipv4|match(\".\"))' "
            iRet = os.system(cmd +f" > {oArgs.output}")

        elif oArgs.nodes == 'select_version':
            assert bHAVE_JQ, "jq is required for this command"
            assert oArgs.output, "--output required for this command"
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_udp)|select(.version|match(\"{sTOX_VERSION}\"))' "
            iRet = os.system(cmd +f" > {oArgs.output}")

        elif oArgs.nodes == 'nmap_tcp':
            assert bHAVE_JQ, "jq is required for this command"
            assert oArgs.output, "--output required for this command"
            if not bAreWeConnected():
                LOG.error(f"{oArgs.nodes} not connected")
                iRet = -1
            else:
                cmd = vBashFileNmapTcp()
                iRet = os.system(f"bash {cmd} < '{sFile}'" +f" >'{oArgs.output}'")
                
        elif oArgs.nodes == 'nmap_udp':
            assert bHAVE_JQ, "jq is required for this command"
            assert oArgs.output, "--output required for this command"
            if not bAreWeConnected():
                LOG.error(f"{oArgs.nodes} not connected")
                iRet = -1
            else:
                cmd = vBashFileNmapUdp()
                iRet = os.system(f"bash {cmd} < '{sFile}'" +f" >'{oArgs.output}'")
                
        elif oArgs.nodes == 'download' and download_url:
            if not bAreWeConnected():
                LOG.error(f"{oArgs.nodes} not connected")
                iRet = -1
            else:
                url = oArgs.download_nodes_url
                bSAVE = download_url(url)
                if not bSAVE:
                    LOG.warn("failed downloading list of nodes")
                    iRet = -1
                else:
                    if oArgs.output:
                        oStream = open(oArgs.output, 'rb')
                        oStream.write(bSAVE)
                    else:
                        oStream = sys.stdout
                        oStream.write(str(bSAVE, 'utf-8'))
                    iRet = -1
                    LOG.info(f"downloaded list of nodes saved to {oStream}")

        if iRet > 0:
            LOG.warn(f"{oArgs.nodes} iRet={iRet} to {oArgs.output}")
        elif iRet == 0:
            LOG.info(f"{oArgs.nodes} iRet={iRet} to {oArgs.output}")
            
    elif oArgs.command == 'info':
        bOUT = b'\x00\x00\x00\x00\x1f\x1b\xed\x15'
        # toxEsave
        assert bSAVE[:8] == bOUT, "Not a Tox profile"

        lOUT = []
        process_chunk(len(bOUT), bSAVE)
        if lOUT:
            if oArgs.output:
                oStream = open(oArgs.output, 'rb')
            else:
                oStream = sys.stdout
            if oArgs.info == 'yaml' and yaml:
                yaml.dump(lOUT, stream=oStream, indent=oArgs.indent)
                oStream.write('\n')
            elif oArgs.info == 'json' and json:
                json.dump(lOUT, oStream, indent=oArgs.indent)
                oStream.write('\n')
            elif oArgs.info == 'repr':
                oStream.write(repr(lOUT))
                oStream.write('\n')
            elif oArgs.info == 'pprint':
                pprint(lOUT, stream=oStream, indent=oArgs.indent, width=80)
            elif oArgs.info == 'info':
                pass
        # were short repacking as we read - 446 bytes missing
        LOG.debug(f"len bSAVE={len(bSAVE)} bOUT={len(bOUT)} delta={len(bSAVE) - len(bOUT)} iTOTAL={iTOTAL}")
    

    if oStream and oStream != sys.stdout and oStream != sys.stderr:
        oStream.close()

    sys.exit(0)
