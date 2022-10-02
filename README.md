# tox_profile

Read and manipulate tox profile files. It started as a simple script from
<https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in>

For the moment logging_tox_savefile.py just reads a Tox profile and
prints to stdout various things that it finds.  Then it writes what it
found in YAML to stderr.  Later it can be extended to print out JSON
or YAML, and then extended to accept JSON or YAML to write a profile.

## Usage

Reads a tox profile and prints out information on what's in there to stderr.
Call it with one argument, the filename of the profile for the decrypt, edit
or info commands, or the filename of the nodes file for the nodes command.

3 commands are supported:
1. ```--command decrypt``` decrypts the profile and writes to the result
to stdout
2. ```--command info``` prints info about what's in the Tox profile to stderr
3. ```--command nodes``` assumes you are reading a json nodes file instead of
  a profile

```
usage: logging_tox_savefile.py [-h] [--output OUTPUT]
                               [--command {info,decrypt,nodes}]
                               [--indent INDENT]
                               [--info {info,repr,yaml,json,pprint,nmap_udp,nmap_tcp}]
                               [--nodes {select_tcp,select_udp,select_version,nmap_tcp,nmap_udp}]
                               [--download_nodes_url DOWNLOAD_NODES_URL]
                               [profile]
```
Positional arguments:
```
  profile               tox profile file - may be encrypted
```
Optional arguments:
```
  -h, --help            show this help message and exit
  --command {info,decrypt,nodes}
                        Action command - default: info
  --output OUTPUT       Destination for info/decrypt/nodes - defaults to stdout
  --info {info,repr,yaml,json,pprint,nmap_udp,nmap_tcp}
                        Format for info command
  --nodes {select_tcp,select_udp,select_version,nmap_tcp,nmap_udp}
                        Action for nodes command (requires jq)
  --indent INDENT       Indent for yaml/json/pprint
  --download_nodes_url DOWNLOAD_NODES_URL
```

### --command info

```info``` will output the profile on stdout, or to a file with ```--output```

Choose one of ```{info,repr,yaml,json,pprint,save}```
for the format for info command.

Choose one of ```{nmap_udp,nmap_tcp}```
to run tests using ```nmap``` for the ```DHT``` and ```TCP_RELAY```
sections of the profile. Reguires ```nmap``` and uses ```sudo```.

#### Saving a copy

The code now can generate a saved copy of the profile as it parses the profile.
Use the command ```--command info --info save``` with ```--output```
and a filename, to process the file with info to stderr, and it will
save an copy of the file to the  ```--output``` (unencrypted).

It may be shorter than the original profile by up to 512 bytes, as the
original toxic profile is padded at the end with nulls (or maybe in the
decryption). 

### --command nodes

Takes a DHTnodes.json file as an argument.
Choose one of ```{select_tcp,select_udp,select_version}```
for ```--nodes``` to select TCP nodes, UDP nodes,
or nodes with the latest version. Requires ```jq```.

Choose one of ```{nmap_tcp,nmap_udp}``` to run tests using ```nmap```
for the ```status_tcp==True``` and ```status_udp==True``` nodes.
Reguires ```nmap``` and uses ```sudo```.

### --command decrypt

Decrypt a profile.

### --command edit

The code now can generate an edited copy of the profile.
Use the command ```--command edit --edit section,key,val``` with
```--output``` and a filename, to process the file with info to stderr,
and it will save an copy of the edited file to the
```--output``` file (unencrypted). There's not much editing yet; give
```--command edit --edit help``` to get a list of what Available Sections,
and Supported Quads (section,num,key,type) that can be edited.
Currently it is:
```
NAME,.,Nick_name,str
STATUSMESSAGE,.,Status_message,str
STATUS,.,Online_status,int
```
The ```num``` field is to accomodate sections that have lists:
* ```.``` is a placeholder for sections that don't have lists.
* ```<int>``` is for the nth element of the list, zero-based.
* ```*``` is for all elements of the list.


## Requirements

If you want to read encrypted profiles, you need to download
toxygen to deal with encrypted tox files, from:
<https://git.plastiras.org/emdee/toxygen_wrapper>
Just put the toxygen/toxygen directory on your PYTHONPATH
You also need to link your libtoxcore.so and libtoxav.so
and libtoxencryptsave.so into ```wrapper/../libs/```
Link all 3 from libtoxcore.so files if you have only libtoxcore.so

If you want to read the GROUPS section, you need Python msgpack:
<https://pypi.org/project/msgpack/>

If you want to write in YAML, you need Python yaml:
<https://pypi.org/project/PyYAML/>

If you have coloredlogs installed it will make use of it: 
<https://pypi.org/project/coloredlogs/>

For the ```select``` and ```nmap``` commands, the ```jq``` utility is
required. It's available in most distros, or <https://stedolan.github.io/jq/>

For the ```nmap``` commands, the ```nmap``` utility is
required. It's available in most distros, or <https://nmap.org/>

## Future Directions

This has not been tested on Windwoes, but is should be simple to fix.

Because it's written in Python it is easy to extend to, for example,
rekeying a profile when copying a profile to a new device:
<https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC>


## Specification

There is a copy of the Tox [spec](https://toktok.ltd/spec.html)
in the repo - it is missing any description of the groups section.
