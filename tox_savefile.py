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
         choices=['info', 'save', 'repr', 'yaml','json', 'pprint']
         with --info=info prints info about the profile to stderr
         nmap_udp        - test DHT nodes with nmap
         nmap_tcp        - test TCP_RELAY nodes with nmap
         nmap_onion      - test PATH_NODE nodes with nmap
         indents the output as: 'yaml','json', 'pprint'
  --indent for pprint/yaml/json default=2

  --output Destination for the command - required
  --nodes
       choices=['select_tcp', 'select_udp', 'nmap_tcp', 'select_version', 'nmap_udp']
       select_udp      - select udp nodes
       select_tcp      - select tcp nodes
       nmap_udp        - test UDP nodes with nmap
       nmap_tcp        - test TCP nodes with nmap
       select_version  - select nodes that are the latest version
       download        - download nodes from --download_nodes_url
  --download_nodes_url https://nodes.tox.chat/json

"""

# originally from:
# https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in

import sys
import os
import time
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
    from wrapper_tests.support_http import download_url, bAreWeConnected
except ImportError as e:
    print(f"Import Error {e}")
    print("Download toxygen_wrapper to deal with encrypted tox files, from:")
    print("https://git.plastiras.org/emdee/toxygen_wrapper")
    print("Just put the parent of the wrapper directory on your PYTHONPATH")
    print("You also need to link your libtoxcore.so and libtoxav.so")
    print("and libtoxencryptsave.so into wrapper/../libs/")
    print("Link all 3 from libtoxcore.so if you have only libtoxcore.so")
    ToxEncryptSave = None
    download_url = None

LOG = logging.getLogger('TSF')

# Fix for Windows
sDIR = os.environ.get('TMPDIR', '/tmp')
sTOX_VERSION = "1000002018"
bHAVE_NMAP = shutil.which('nmap')
bHAVE_JQ = shutil.which('jq')
bHAVE_BASH = shutil.which('bash')
bMARK = b'\x00\x00\x00\x00\x1f\x1b\xed\x15'
bDEBUG = 'DEBUG' in os.environ and os.environ['DEBUG'] != 0
def trace(s): LOG.log(LOG.level, '+ ' +s)
LOG.trace = trace

global bOUT, aOUT, sENC
aOUT = {}
bOUT = b''
sENC = 'utf-8'
# grep '#''#' logging_tox_savefile.py|sed -e 's/.* //'
sEDIT_HELP = """
NAME,.,Nick_name,str
STATUSMESSAGE,.,Status_message,str
STATUS,.,Online_status,int
"""

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
        name = str(result[o:o+nsize], sENC)

        o = delta+1+32+1024+1+2+128+2+1007; l = 2
        msize = struct.unpack_from(">H", result, o)[0]
        o = delta+1+32+1024+1+2+128+2; l = 1007
        mame = str(result[o:o+msize], sENC)
        LOG.info(f"Friend #{i}  {dStatus[status]} {name} {pk}")
        lIN += [{"Status": dStatus[status],
                 "Name": name,
                 "Pk": pk}]
    return lIN

def lProcessGroups(state, index, length, result, label="GROUPS"):
    """
    No GROUPS description in spec.html
    """
    global sENC
    lIN = []
    i = 0
    if not msgpack:
        LOG.warn(f"process_chunk Groups = NO msgpack bytes={length}")
        return []
    try:
        groups = msgpack.loads(result, raw=True)
        LOG.info(f"{label} {len(groups)} groups")
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
            dBINS = {"Version": version,
                     "Privacy_state": privacy_state}
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
            topic_info_topic = str(topic_info[3], sENC)
            LOG.info(f"lProcessGroups #{i} topic_info_topic={topic_info_topic}")
            dBINS = {"topic_info_topic": topic_info_topic}
            lIN += [{"Topic_info": dBINS}]

            assert len(mod_list) == 2, mod_list
            num_moderators = mod_list[0]
            LOG.info(f"lProcessGroups #{i} num moderators={mod_list[0]}")
            #define CRYPTO_SIGN_PUBLIC_KEY_SIZE    32
            mods = mod_list[1]
            assert len(mods) % 32 == 0, len(mods)
            assert len(mods) == num_moderators * 32, len(mods)
            lMODS = []
            for j in range(num_moderators):
                mod = mods[j*32:j*32 + 32]
                LOG.info(f"lProcessGroups group#{i} mod#{j} sig_pk={bin_to_hex(mod)}")
                lMODS += [{"Sig_pk": bin_to_hex(mod)}]
            lIN += [{"Moderators": lMODS}]

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
            self_nick = str(self_nick, sENC)
            LOG.info(f"lProcessGroups #{i} self_nick={self_nick}")
            dBINS = {"Self_nick": self_nick}
            lIN += [{"Self_info": dBINS}]

            assert len(saved_peers) == 2, saved_peers

    except Exception as e:
        LOG.warn(f"process_chunk Groups #{i} error={e}")
    return lIN

def lProcessNodeInfo(state, index, length, result, label="DHTnode"):
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
            prot = 'TCP'
            af = status - 128
        else:
            prot = 'UDP'
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
        LOG.info(f"{label} #{relay} bytes={length} status={status} prot={prot} af={af} ip={ipaddr} port={port} pk={pk}")
        lIN += [{"Bytes": length,
                 "Status": status,
                 "Prot": prot,
                 "Af": af,
                 "Ip": ipaddr,
                 "Port": port,
                 "Pk": pk}]
        delta += total
        length -= total
        relay += 1
    return lIN

def lProcessDHTnodes(state, index, length, result, label="DHTnode"):
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
            prot = 'UDP'
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

            LOG.info(f"{label} #{relay} status={status} ipaddr={ipaddr} port={port} {pk}")
            lIN += [{
                "Status": status,
                "Prot": prot,
                "Af": af,
                "Ip": ipaddr,
                "Port": port,
                "Pk": pk}]
            offset += subtotal
        delta += total
        length -= total
        relay += 1
    return lIN

def process_chunk(index, state, oArgs=None):
    global bOUT, aOUT
    global sENC

    length = struct.unpack_from("<I", state, index)[0]
    data_type = struct.unpack_from("<H", state, index + 4)[0]
    check = struct.unpack_from("<H", state, index + 6)[0]
    assert check == 0x01CE, check
    new_index = index + length + 8
    result = state[index + 8:index + 8 + length]

    label = dSTATE_TYPE[data_type]
    if oArgs.command == 'edit' and oArgs.edit:
        section,num,key,val = oArgs.edit.split(',',3)

    diff =  index - len(bOUT)
    if bDEBUG and diff > 0:
        LOG.warn(f"PROCESS_CHUNK {label} index={index} bOUT={len(bOUT)} delta={diff} length={length}")
    elif bDEBUG:
        LOG.trace(f"PROCESS_CHUNK {label} index={index} bOUT={len(bOUT)} delta={diff} length={length}")

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
        aOUT.update({label: aIN})

    elif data_type == MESSENGER_STATE_TYPE_DHT:
        LOG.debug(f"process_chunk {label} length={length}")
        lIN = lProcessDHTnodes(state, index, length, result)
        aOUT.update({label: lIN})

    elif data_type == MESSENGER_STATE_TYPE_FRIENDS:
        LOG.info(f"{label} {length // 2216} FRIENDS {length % 2216}")
        lIN = lProcessFriends(state, index, length, result)
        aOUT.update({label: lIN})

    elif data_type == MESSENGER_STATE_TYPE_NAME:
        name = str(result, sENC)
        LOG.info(f"{label} Nick_name = " +name)
        aIN = {"Nick_name": name}
        aOUT.update({label: aIN})
        if oArgs.command == 'edit' and section == label:
            ## NAME,.,Nick_name,str
            if key == "Nick_name":
                result = bytes(val, sENC)
                length = len(result)
                LOG.info(f"{label} {key} EDITED to {val}")

    elif data_type == MESSENGER_STATE_TYPE_STATUSMESSAGE:
        mess = str(result, sENC)
        LOG.info(f"{label} StatusMessage = " +mess)
        aIN = {"Status_message": mess}
        aOUT.update({label: aIN})
        if oArgs.command == 'edit' and section == label:
            ## STATUSMESSAGE,.,Status_message,str
            if key == "Status_message":
                result = bytes(val, sENC)
                length = len(result)
                LOG.info(f"{label} {key} EDITED to {val}")

    elif data_type == MESSENGER_STATE_TYPE_STATUS:
        # 1  uint8_t status (0 = online, 1 = away, 2 = busy)
        dStatus = {0: 'online', 1: 'away', 2: 'busy'}
        status = struct.unpack_from(">b", state, index)[0]
        status = dStatus[status]
        LOG.info(f"{label} = " +status)
        aIN = {f"Online_status": status}
        aOUT.update({label: aIN})
        if oArgs.command == 'edit' and section == label:
            ## STATUS,.,Online_status,int
            if key == "Online_status":
                result = struct.pack(">b", int(val))
                length = len(result)
                LOG.info(f"{label} {key} EDITED to {val}")

    elif data_type == MESSENGER_STATE_TYPE_GROUPS:
        if length > 0:
            lIN = lProcessGroups(state, index, length, result, label)
        else:
            lIN = []
            LOG.info(f"NO {label}")
        aOUT.update({label: lIN})

    elif data_type == MESSENGER_STATE_TYPE_TCP_RELAY:
        if length > 0:
            lIN = lProcessNodeInfo(state, index, length, result, "TCPnode")
        else:
            lIN = []
            LOG.info(f"NO {label}")
        aOUT.update({label: lIN})

    elif data_type == MESSENGER_STATE_TYPE_PATH_NODE:
        #define NUM_SAVED_PATH_NODES 8
        if not length % 8 == 0:
            # this should be an assert?
            LOG.warn(f"process_chunk {label} mod={length % 8}")
        else:
            LOG.debug(f"process_chunk {label} bytes={length}")
        lIN = lProcessNodeInfo(state, index, length, result, "PATHnode")
        aOUT.update({label: lIN})

    elif data_type == MESSENGER_STATE_TYPE_CONFERENCES:
        lIN = []
        if length > 0:
            LOG.debug(f"TODO process_chunk {label} bytes={length}")
        else:
            LOG.info(f"NO {label}")
        aOUT.update({label: []})

    elif data_type != MESSENGER_STATE_TYPE_END:
        LOG.error("UNRECOGNIZED datatype={datatype}")
        sys.exit(1)

    else:
        LOG.info("END") # That's all folks...
        # drop through

    # We repack as we read: or edit as we parse; simply edit result and length.
    # We'll add the results back to bOUT to see if we get what we started with.
    # Then will will be able to selectively null sections or selectively edit.
    assert length == len(result), length
    bOUT += struct.pack("<I", length) + \
        struct.pack("<H", data_type) + \
        struct.pack("<H", check) + \
        result

    if data_type == MESSENGER_STATE_TYPE_END or index + 8 >= len(state):
        diff = len(bSAVE) - len(bOUT)
        if oArgs.command != 'edit' and diff > 0:
            # if short repacking as we read - tox_profile is padded with nulls
            LOG.warn(f"PROCESS_CHUNK bSAVE={len(bSAVE)} bOUT={len(bOUT)} delta={diff}")
        return

    process_chunk(new_index, state, oArgs)

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
	    echo DBUG $cmd $ip
	    $cmd $ip | grep /tcp
	fi
	ip=""
	continue
    else
	port=`echo $line|sed -e 's/,//'`
	ports+=($port)
    fi
done"""

def vBashFileNmapTcp():
    assert bHAVE_JQ, "jq is required for this command"
    assert bHAVE_NMAP, "nmap is required for this command"
    assert bHAVE_BASH, "bash is required for this command"
    f = "NmapTcp.bash"
    sFile = os.path.join(sDIR, f)
    if not os.path.exists(sFile):
        with open(sFile, 'wt') as iFd:
            iFd.write(sNMAP_TCP)
        os.chmod(sFile, 0o0775)
    return sFile

def vBashFileNmapUdp():
    assert bHAVE_JQ, "jq is required for this command"
    assert bHAVE_NMAP, "nmap is required for this command"
    assert bHAVE_BASH, "bash is required for this command"
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

def vOsSystemNmapUdp(l, oArgs):
    iErrs = 0
    for elt in aOUT["DHT"]:
        cmd = f"sudo nmap -Pn -n -sU -p U:{elt['Port']} {elt['Ip']}"
        iErrs += os.system(cmd +f" >> {oArgs.output} 2>&1")
    if iErrs:
        LOG.warn(f"{oArgs.info} {iErrs} ERRORs to {oArgs.output}")
        print(f"{oArgs.info} {iErrs} ERRORs to {oArgs.output}")
    else:
        LOG.info(f"{oArgs.info} NO errors to {oArgs.output}")
        print(f"{oArgs.info} NO errors to {oArgs.output}")

def vOsSystemNmapTcp(l, oArgs):
    iErrs = 0
    for elt in l:
        cmd = f"sudo nmap -Pn -n -sT -p T:{elt['Port']} {elt['Ip']}"
        print(f"{oArgs.info} NO errors to {oArgs.output}")
        iErrs += os.system(cmd +f" >> {oArgs.output} 2>&1")
    if iErrs:
        LOG.warn(f"{oArgs.info} {iErrs} ERRORs to {oArgs.output}")
        print(f"{oArgs.info} {iErrs} ERRORs to {oArgs.output}")
    else:
        LOG.info(f"{oArgs.info} NO errors to {oArgs.output}")
        print(f"{oArgs.info} NO errors to {oArgs.output}")

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
                        choices=['info', 'decrypt', 'nodes', 'edit'],
                        required=True,
                        help='Action command - default: info')
    parser.add_argument('--edit', type=str, default='',
                        help='comma seperated SECTION,key,value - unfinished')
    parser.add_argument('--indent', type=int, default=2,
                        help='Indent for yaml/json/pprint')
    choices=['info', 'save', 'repr', 'yaml','json', 'pprint']
    if bHAVE_NMAP: choices += ['nmap_tcp', 'nmap_udp', 'nmap_onion']
    parser.add_argument('--info', type=str, default='info',
                        choices=choices,
                        help='Format for info command')
    choices = []
    if bHAVE_JQ:
        choices += ['select_tcp', 'select_udp', 'select_version']
    if bHAVE_NMAP: choices += ['nmap_tcp', 'nmap_udp']
    if download_url:
        choices += ['download']
    parser.add_argument('--nodes', type=str, default='',
                        choices=choices,
                        help='Action for nodes command (requires jq)')
    parser.add_argument('--download_nodes_url', type=str,
                        default='https://nodes.tox.chat/json')
    parser.add_argument('--encoding', type=str, default=sENC)
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='tox profile file - may be encrypted')
    return parser

if __name__ == '__main__':
    lArgv = sys.argv[1:]
    parser = oMainArgparser()
    oArgs = parser.parse_args(lArgv)
    if oArgs.command in ['edit'] and oArgs.edit == 'help':
        l = list(dSTATE_TYPE.values())
        l.remove('END')
        print('Available Sections: ' +repr(l))
        print('Supported Quads: section,num,key,type ' +sEDIT_HELP)
        sys.exit(0)

    sFile = oArgs.profile
    assert os.path.isfile(sFile), sFile

    sENC = oArgs.encoding
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
        assert oArgs.output, "--output required for this command"
        oStream = open(oArgs.output, 'wb')
        iRet = oStream.write(bSAVE)
        LOG.info(f"Wrote {iRet} to {oArgs.output}")
        iRet = 0

    elif oArgs.command == 'nodes':
        iRet = -1
        ep_sec = str(int(time.time()))
        json_head = '{"last_scan":' +ep_sec \
          +',"last_refresh":' +ep_sec \
          +',"nodes":['
        if oArgs.nodes == 'select_tcp':
            assert oArgs.output, "--output required for this command"
            assert bHAVE_JQ, "jq is required for this command"
            with open(oArgs.output, 'wt') as oFd:
                oFd.write(json_head)                
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_tcp)|select(.ipv4|match(\".\"))' "
            iRet = os.system(cmd +"| sed -e '2,$s/^{/,{/'" +f" >>{oArgs.output}")
            with open(oArgs.output, 'at') as oFd: oFd.write(']}\n')

        elif oArgs.nodes == 'select_udp':
            assert oArgs.output, "--output required for this command"
            assert bHAVE_JQ, "jq is required for this command"
            with open(oArgs.output, 'wt') as oFd:
                oFd.write(json_head)                
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_udp)|select(.ipv4|match(\".\"))' "
            iRet = os.system(cmd +"| sed -e '2,$s/^{/,{/'" +f" >>{oArgs.output}")
            with open(oArgs.output, 'at') as oFd: oFd.write(']}\n')

        elif oArgs.nodes == 'select_version':
            assert bHAVE_JQ, "jq is required for this command"
            assert oArgs.output, "--output required for this command"
            with open(oArgs.output, 'wt') as oFd:
                oFd.write(json_head)                
            cmd = f"cat '{sFile}' | jq '.|with_entries(select(.key|match(\"nodes\"))).nodes[]|select(.status_udp)|select(.version|match(\"{sTOX_VERSION}\"))'" 
                
            iRet = os.system(cmd +"| sed -e '2,$s/^{/,{/'" +f" >>{oArgs.output}")
            with open(oArgs.output, 'at') as oFd:
                oFd.write(']}\n')

        elif oArgs.nodes == 'nmap_tcp':
            assert oArgs.output, "--output required for this command"
            if not bAreWeConnected():
                LOG.warn(f"{oArgs.nodes} we are not connected")
            cmd = vBashFileNmapTcp()
            iRet = os.system(f"bash {cmd} < '{sFile}'" +f" >'{oArgs.output}'")

        elif oArgs.nodes == 'nmap_udp':
            assert oArgs.output, "--output required for this command"
            if not bAreWeConnected():
                LOG.warn(f"{oArgs.nodes} we are not connected")
            cmd = vBashFileNmapUdp()
            iRet = os.system(f"bash {cmd} < '{sFile}'" +f" >'{oArgs.output}'")

        elif oArgs.nodes == 'download' and download_url:
            if not bAreWeConnected():
                LOG.warn(f"{oArgs.nodes} we are not connected")
            url = oArgs.download_nodes_url
            b = download_url(url)
            if not bSAVE:
                LOG.warn("failed downloading list of nodes")
                iRet = -1
            else:
                if oArgs.output:
                    oStream = open(oArgs.output, 'rb')
                    oStream.write(b)
                else:
                    oStream = sys.stdout
                    oStream.write(str(b, sENC))
                iRet = -1
                LOG.info(f"downloaded list of nodes to {oStream}")

        if iRet > 0:
            LOG.warn(f"{oArgs.nodes} iRet={iRet} to {oArgs.output}")
        elif iRet == 0:
            LOG.info(f"{oArgs.nodes} iRet={iRet} to {oArgs.output}")

    elif oArgs.command in ['info', 'edit']:
        if oArgs.command in ['edit']:
            assert oArgs.output, "--output required for this command"
            assert oArgs.edit != '', "--edit required for this command"
        elif oArgs.command == 'info':
            # assert oArgs.info != '', "--info required for this command"
            if oArgs.info in ['save', 'yaml', 'json', 'repr', 'pprint']:
                assert oArgs.output, "--output required for this command"

        # toxEsave
        assert bSAVE[:8] == bMARK, "Not a Tox profile"
        bOUT = bMARK

        iErrs = 0
        process_chunk(len(bOUT), bSAVE, oArgs)
        if not bOUT:
            LOG.error(f"{oArgs.command} NO bOUT results")
        else:
            oStream = None
            LOG.debug(f"command={oArgs.command} len bOUT={len(bOUT)} results")

            if oArgs.command in ['edit'] or oArgs.info in ['save']:
                LOG.debug(f"{oArgs.command} saving to {oArgs.output}")
                oStream = open(oArgs.output, 'wb', encoding=None)
                if oStream.write(bOUT) > 0: iRet = 0
                LOG.info(f"{oArgs.info}ed iRet={iRet} to {oArgs.output}")
            elif oArgs.info == 'info':
                pass
            elif oArgs.info == 'yaml' and yaml:
                LOG.debug(f"{oArgs.command} saving to {oArgs.output}")
                oStream = open(oArgs.output, 'wt', encoding=sENC)
                yaml.dump(aOUT, stream=oStream, indent=oArgs.indent)
                if oStream.write('\n') > 0: iRet = 0
                LOG.info(f"{oArgs.info}ing iRet={iRet} to {oArgs.output}")
            elif oArgs.info == 'json' and json:
                LOG.debug(f"{oArgs.command} saving to {oArgs.output}")
                oStream = open(oArgs.output, 'wt', encoding=sENC)
                json.dump(aOUT, oStream, indent=oArgs.indent)
                if oStream.write('\n') > 0: iRet = 0
                LOG.info(f"{oArgs.info}ing iRet={iRet} to {oArgs.output}")
            elif oArgs.info == 'repr':
                LOG.debug(f"{oArgs.command} saving to {oArgs.output}")
                oStream = open(oArgs.output, 'wt', encoding=sENC)
                if oStream.write(repr(bOUT)) > 0: iRet = 0
                if oStream.write('\n') > 0: iRet = 0
                LOG.info(f"{oArgs.info}ing iRet={iRet} to {oArgs.output}")
            elif oArgs.info == 'pprint':
                LOG.debug(f"{oArgs.command} saving to {oArgs.output}")
                oStream = open(oArgs.output, 'wt', encoding=sENC)
                pprint(aOUT, stream=oStream, indent=oArgs.indent, width=80)
                iRet = 0
                LOG.info(f"{oArgs.info}ing iRet={iRet} to {oArgs.output}")
            elif oArgs.info == 'nmap_tcp' and bHAVE_NMAP:
                assert oArgs.output, "--output required for this command"
                vOsSystemNmapTcp(aOUT["TCP_RELAY"], oArgs)
            elif oArgs.info == 'nmap_udp' and bHAVE_NMAP:
                assert oArgs.output, "--output required for this command"
                vOsSystemNmapUdp(aOUT["DHT"], oArgs)
            elif oArgs.info == 'nmap_onion' and bHAVE_NMAP:
                assert oArgs.output, "--output required for this command"
                vOsSystemNmapUdp(aOUT["PATH_NODE"], oArgs)

    if oStream and oStream != sys.stdout and oStream != sys.stderr:
        oStream.close()

    sys.exit(0)
