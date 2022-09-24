# -*- mode: text; indent-tabs-mode: nil; coding: utf-8 -*-

# tox_profile

Read and manipulate tox profile files. It started as a simple script from
<https://stackoverflow.com/questions/30901873/what-format-are-tox-files-stored-in>

For the moment logging_tox_savefile.py just reads a Tox profile
and prints to stdout various things that it finds. Later it can
be extended to print out JSON or YAML, and then extended to
accept JSON or YAML to write a profile.

## Requirements

If you want to read encrypted profiles, you need to download
toxygen to deal with encrypted tox files, from:
<https://github.com/toxygen-project/toxygen>
Just put the toxygen/toxygen directory on your PYTHONPATH
You also need to link your libtoxcore.so and libtoxav.so
and libtoxencryptsave.so into toxygen/toxygen/libs/
Link all 3 from libtoxcore.so files if you have only libtoxcore.so

If you want to read the GROUPS section, you need Python msgpack:
<https://pypi.org/project/msgpack/>

If you have coloredlogs installed it will make use of it: 
<https://pypi.org/project/coloredlogs/>

## Future Directions

Because it's written in Python it is easy to extend to, for example,
rekeying a profile when copying a profile to a new device:
<https://git.plastiras.org/emdee/tox_profile/wiki/MultiDevice-Announcements-POC>

