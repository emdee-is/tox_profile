# tox_profile

Read and manipulate tox profile files. It started as a simple script from
<https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in>

```tox_profile.py``` reads a Tox profile and prints to stderr various
things that it finds.  Then can write what it found in JSON/YAML/REPR/PPRINT
to a file. It can also test the nodes in a profile using ```nmap```.

( There are sometimes problems with the json info dump of bytes keys:
```TypeError: Object of type bytes is not JSON serializable```)

It can also download, select, or test nodes in a ```DHTnode.json``` file.

It can also decrypt a profile, saving the output to a file.

It can also edit a profile, changing a few select fields.
Later it can be extended to edit more crucial fields.

## Usage

Reads a tox profile and prints out information on what's in there to stderr.
Call it with one argument, the filename of the profile for the decrypt, edit
or info commands, or the filename of the nodes file for the nodes command.

4 commands are supported:
1. ```--command decrypt``` decrypts the profile and writes to the result
to stdout
2. ```--command info``` prints info about what's in the Tox profile to stderr
3. ```--command nodes``` assumes you are reading a json nodes file instead of
  a profile
4. ```--command edit``` edits the profile and writes to the result
to a file.

```
usage: tox_profile.py [-h]
       [--command info|decrypt|nodes|edit|onions]
       [--info info|repr|yaml|json|pprint|nmap_dht|nmap_relay]
       [--indent INDENT]
       [--nodes select_tcp|select_udp|select_version|nmap_tcp|nmap_udp|download|check|clean]
       [--download_nodes_url DOWNLOAD_NODES_URL]
       [--edit help|section,num,key,val]
       [--output OUTPUT]
        profile		       
```
Positional arguments:
```
  profile               tox profile file - may be encrypted
```
Optional arguments:
```
  -h, --help            show this help message and exit
  --command {info,decrypt,nodes,edit}
                        Action command - default: info
  --output OUTPUT       Destination for info/decrypt/nodes - can be the same as input
  --info info|repr|yaml|json|pprint|nmap_dht|nmap_relay (may require nmap)
                        Format for info command
  --indent INDENT       Indent for yaml/json/pprint
  --nodes select_tcp|select_udp|select_version|nmap_tcp|nmap_udp|download
                        Action for nodes command (requires jq and nmap)
  --download_nodes_url DOWNLOAD_NODES_URL
  --edit help|section,num,key,val
```

### --command info

```info``` will output the profile on stdout, or to a file with ```--output```

Choose one of ```{info,repr,yaml,json,pprint,save}```
for the format for info command.

Choose one of ```{nmap_dht,nmap_relay,nmap_path}```
to run tests using ```nmap``` for the ```DHT``` and ```TCP_RELAY```
sections of the profile. Reguires ```nmap``` and uses ```sudo```.

```
  --info default='info',
         choices=[info, save, repr, yaml,json, pprint]
         with --info=info prints info about the profile to stderr
         yaml,json, pprint, repr - output format
         nmap_dht        - test DHT nodes with nmap
         nmap_relay        - test TCP_RELAY nodes with nmap
         nmap_path      - test PATH_NODE nodes with nmap
  --indent for pprint/yaml/json default=2


```

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

Choose ```download``` to download the nodes from ```--download_nodes_url```

Choose ```check``` to check the  downloaded nodes, and the error return
is the number of nodes with errors. 

Choose ```clean``` to clean the  downloaded nodes, and give
```--output``` for the file the  nodes ckeaned of  errors.

Check and clean will also try to ping the nodes on the relevant ports,
and clean will update the ```status_tcp``, ```status_udp```, and
```last_ping``` fields of the nodes.

  --nodes
       choices=[select_tcp, select_udp, nmap_tcp, select_version, nmap_udp, check, download]
       select_udp      - select udp nodes
       select_tcp      - select tcp nodes
       nmap_udp        - test UDP nodes with nmap
       nmap_tcp        - test TCP nodes with nmap
       select_version  - select nodes that are the latest version
       download        - download nodes from --download_nodes_url
       check           - check nodes from --download_nodes_url
       clean           - check nodes and save them as --output
  --download_nodes_url https://nodes.tox.chat/json
```

### --command decrypt

Decrypt a profile, with ```--output``` to a filename.

### --command edit

The code now can generate an edited copy of the profile.
Use the command ```--command edit --edit section,num,key,val``` with
```--output``` and a filename, to process the file with info to stderr,
and it will save an copy of the edited file to the
```--output``` file (unencrypted). There's not much editing yet; give
```--command edit --edit help``` to get a list of what Available Sections,
and Supported Quads ```(section,num,key,type)``` that can be edited.
Currently it is:
```
NAME,.,Nick_name,str
STATUSMESSAGE,.,Status_message,str
STATUS,.,Online_status,int
NOSPAMKEYS,.,Nospam,hexstr
NOSPAMKEYS,.,Public_key,hexstr
NOSPAMKEYS,.,Private_key,hexstr
```
The ```num``` field is to accomodate sections that have lists:
* ```.``` is a placeholder for sections that don't have lists.
* ```<int>``` is for the nth element of the list, zero-based.
* ```*``` is for all elements of the list.

The ```--output``` can be the same as input as the input file is read
and closed before processing starts.

```
  --edit
       help               - print a summary of what fields can be edited
      section,num,key,val - edit the field section,num,key with val
```

You can use the ```---edit``` command to synchronize profiles, by
keeping the keypair and synchronize profiles between different clients:
e.g. your could keep your profile from toxic as master, and copy it over
your qtox/toxygen/TriFa profile while preserving their keypair and NOSPAM:

1. Use ```--command info --info info``` on the target profile to get the
   ```Nospam```, ```Public_key``` and ```Private_key``` of the target.
2. Backup the target and copy the source profile to the target.
3. Edit the target with the values from 1) with:
```
--command edit --edit NOSPAMKEYS,.,Nospam,hexstr --output target target
--command edit --edit NOSPAMKEYS,.,Public_key,hexstr --output target target
--command edit --edit NOSPAMKEYS,.,Private_key,hexstr --output target target
```

## Requirements

If you want to read encrypted profiles, you need to download
toxygen_wrapper to deal with encrypted tox files, from:
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

## Issues

https://git.plastiras.org/emdee/tox_profile/issues

## Future Directions

This has not been tested on Windwoes, but is should be simple to fix.

Because it's written in Python it is easy to extend to, for example,
supporting multidevices:
<https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC>

There are a couple of bash scripts to show usage:
* tox_profile_examples.bash - simple example usage
* tox_profile_test.bash - a real test runner that still needs documenting.

## Specification

There is a copy of the Tox [spec](https://toktok.ltd/spec.html)
in the repo - it is missing any description of the groups section.

Work on this project is suspended until the
[MultiDevice](https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC) problem is solved. Fork me!
