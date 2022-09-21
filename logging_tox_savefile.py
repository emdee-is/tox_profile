# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

# https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in
import sys
import os
import struct
from socket import inet_ntop, AF_INET6, AF_INET
try:
    # https://github.com/toxygen-project/toxygen
    from wrapper.toxencryptsave import ToxEncryptSave
except ImportError as e:
    print("Download toxygen to deal with encrypted tox files, from:")
    print("https://github.com/toxygen-project/toxygen")
    print("Just put the toxygen/toxygen directory on your PYTHONPATH")
    print("You also need to link your libtoxcore.so and libtoxav.so")
    print("and libtoxencryptsave.so into toxygen/toxygen/libs/")
    print("Link all 3 from libtoxcore.so if you have only libtoxcore.so")
    ToxEncryptSave = None

try:
    # https://pypi.org/project/coloredlogs/
    import coloredlogs
    if 'COLOREDLOGS_LEVEL_STYLES' not in os.environ:
        os.environ['COLOREDLOGS_LEVEL_STYLES'] = 'spam=22;debug=28;verbose=34;notice=220;warning=202;success=118,bold;error=124;critical=background=red'
except ImportError as e:
    coloredlogs = False

global LOG
import logging
LOG = logging.getLogger()

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
        LOG.warn('Not encrypted')
        return data
    assert data[:8] == b'toxEsave', data[:8]

    sys.stdout.flush()
    password = getpass('Password: ')
    assert password
    newData = oToxES.pass_decrypt(data, password)
    LOG.debug('Decrypted: ' +str(len(newData)) +' bytes')
    return newData

def bin_to_string(raw_id, length=None):
    if length is None: length = len(raw_id)
    res = ''.join('{:02x}'.format(ord(raw_id[i])) for i in range(length))
    return res.upper()

def bin_to_str(raw_id, length=None):
    if length is None: length = len(raw_id)
    res = ''.join('{:02x}'.format(raw_id[i]) for i in range(length))
    return res.upper()

def process_chunk(index, state):
    if index + 8 >= len(state):
        return
    length = struct.unpack_from("<H", state, index)[0]
    new_index = index + length + 8
    data_type = struct.unpack_from("<H", state, index + 4)[0]

    if data_type == MESSENGER_STATE_TYPE_NOSPAMKEYS:
        result = state[index + 8:index + 8 + length]
        nospam = bin_to_str(result[0:4])
        public_key = bin_to_str(result[4:36])
        private_key = bin_to_str(result[36:68])
        LOG.info(f"nospam = {nospam}")
        LOG.info(f"public_key = {public_key}")
        LOG.info(f"private_key = {private_key}")

    elif data_type == MESSENGER_STATE_TYPE_DHT:
        relay = 0
        result = state[index + 8:index + 8 + length]
        status = struct.unpack_from("<L", result, 0)[0]
        # 4  uint32_t (0x159000D)
        assert status == 0x159000D
        LOG.debug(f"process_chunk {dSTATE_TYPE[data_type]} length={length}")
        length -= 4
        delta = 4
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
                port = struct.unpack_from(">H", result, offset+8+1+alen)[0]
                pk = bin_to_str(result[offset+8+1+alen+2:offset+8+1+alen+2+32], 32)
               
                LOG.info(f"{dSTATE_TYPE[data_type]} #{relay} status={status} ipaddr={ipaddr} port={port} {pk}")
                offset += subtotal                
            delta += total
            length -= total
            relay += 1

    elif data_type == MESSENGER_STATE_TYPE_FRIENDS:
        """
Friend:

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
                   0:  'Not a friend ',
                   1:  'Friend added ',
                   2: 'Friend request sent ',
                   3: 'Confirmed friend ',
                   4: 'Friend online '
                   }
        result = state[index + 8:index + 8 + length]
        slen = 1+32+1024+1+2+128+2+1007+1+2+1+3+4+8 # 2216
        LOG.debug(f"TODO process_chunk {length // slen} FRIENDS {length} {length % 2216}")
        assert length % slen == 0
        for i in range(length // slen):
            delta = i*slen
            status = struct.unpack_from(">b", result, delta)[0]
            o = delta+1; l = 32
            pk = bin_to_str(result[o:o+l], l)
            
            o = delta+1+32+1024+1+2+128; l = 2
            nsize = struct.unpack_from(">H", result, o)[0]
            o = delta+1+32+1024+1+2; l = 128
            name = str(result[o:o+nsize], 'utf-8')

            o = delta+1+32+1024+1+2+128+2+1007; l = 2
            msize = struct.unpack_from(">H", result, o)[0]
            o = delta+1+32+1024+1+2+128+2; l = 1007
            mame = str(result[o:o+msize], 'utf-8')
            LOG.info(f"Friend #{i} {dStatus[status]} {name} {pk}")

    elif data_type == MESSENGER_STATE_TYPE_NAME:
        LOG.info("User name = {}".format(str(state[index + 8:index + 8 + length], 'utf-8')))

    elif data_type == MESSENGER_STATE_TYPE_STATUSMESSAGE:
        LOG.info(f"StatusMessage = {str(state[index + 8:index + 8 + length], 'utf-8')}")
        
    elif data_type == MESSENGER_STATE_TYPE_STATUS:
        # 1  uint8_t status (0 = online, 1 = away, 2 = busy)
        dStatus = {0: 'online', 1: 'away', 2: 'busy'}
        status = struct.unpack_from(">b", state, index)[0]
        LOG.info(f"{dSTATE_TYPE[data_type]} = {dStatus[status]}")
        
    elif data_type == MESSENGER_STATE_TYPE_GROUPS:
        LOG.debug(f"TODO process_chunk {dSTATE_TYPE[data_type]} bytes={length}")
    elif data_type == MESSENGER_STATE_TYPE_TCP_RELAY:
        """Node Info (packed node format)

The Node Info data structure contains a Transport Protocol, a Socket
Address, and a Public Key. This is sufficient information to start
communicating with that node. The binary representation of a Node Info is
called the “packed node format”.

  Length  Type  Contents    
  1 bit  Transport Protocol  UDP = 0, TCP = 1    
  7 bit  Address Family  2 = IPv4, 10 = IPv6    
  4 \| 16  IP address  4 bytes for IPv4, 16 bytes for IPv6    
  2  Port Number  Port number    
  32  Public Key  Node ID    

"""
        delta = 0
        relay = 0
        result = state[index + 8:index + 8 + length]
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
            port = struct.unpack_from(">H", result, delta+1+alen)[0]
            pk = bin_to_str(result[delta+1+alen+2:delta+1+alen+2+32], 32)
            LOG.info(f"{dSTATE_TYPE[data_type]} #{relay} bytes={length} {status} {ipv} {af} {ipaddr} {port} {pk}")
            delta += total
            length -= total
            relay += 1
            
    elif data_type == MESSENGER_STATE_TYPE_PATH_NODE:
        LOG.debug(f"TODO process_chunk {dSTATE_TYPE[data_type]} bytes={length}")
    elif data_type == MESSENGER_STATE_TYPE_CONFERENCES:
        if length > 0:
            LOG.debug(f"TODO process_chunk {dSTATE_TYPE[data_type]} bytes={length}")
        else:
            LOG.info(f"NO {dSTATE_TYPE[data_type]}")
    elif data_type == MESSENGER_STATE_TYPE_END:
        LOG.info("That's all folks...")

    process_chunk(new_index, state)

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

if __name__ == '__main__':
    if len(sys.argv) > 1:
        sFile = sys.argv[1]
    else:
        sFile = "./tox_save.tox"
    assert os.path.isfile(sFile), sFile

    vSetupLogging()

    if not ToxEncryptSave:
        oSave = open(sFile, 'rb').read()
    else:
        try:
            with open(sFile, 'rb') as iFd:
                oSave = decrypt_data(iFd.read())
        except Exception as e:
            LOG.error(f"decrypting {sFile}\n{e}\n")
            sys.exit(1)

    assert oSave
    assert oSave[:8] == b'\x00\x00\x00\x00\x1f\x1b\xed\x15'
    process_chunk(8, oSave)
