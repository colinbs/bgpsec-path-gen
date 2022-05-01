# bgpsec-path-gen

This tool is used to generate authentic BGPsec Updates containing valid and verifyable signatures. Updates are written to an ouputfile and are stored in binary format. Such files are requied by the [bgpsec-router](https://github.com/colinbs/bgpsec-router) tool.

The way `bgpsec-path-gen` works is the following: using real-world data in form of BGP-Update dumps (download [here](http://archive.routeviews.org/)), and fake data in form of pre-generated keys, BGPsec paths are generated. The process itself is identical as if a routing suite would create actual BGPsec paths. For this purpose, RTRlib is required, as it implements all the required functionalities that are necessary. These are:

1. structuring/assembling the path attribute
2. signing the path attribute

Prior to reading the BGP-Update dump, it must be first transformed into human-readable format utilizing [bgpdump](http://www.ris.ripe.net/source/bgpdump/).

```
bgpdump -O updates.dump -m updates.20220501.1715.bz2
```

The produced file `updates.dump` serves as input for bgpsec-path-gen. `bgpsec-path-gen` will read a line of a given BGP-Update dump and extract the relevant information required to build a valid BGPsec update.

Further, to generate valid BGPsec updates, router certificates are necessary. They can be generated using the [spki-cache-server](https://github.com/colinbs/spki-cache-server) tool.

# How to build

CMake and [rtrlib](https://github.com/rtrlib/rtrlib) headers are required to build the tool. Build the tool as follows:

```
cmake .
make
```

# Usage

Here are some examples, how this tool can be used.

```
./bgpsecpgbin -r updates.dump -k keys/ -o bgpsec-updates.bin -m 10
```

This will result in a file containing 10 BGPsec updates in binary format.

* `-r updates.dump` is the file that was generated using `bgpdump`
* `-k keys/` is the directory that stores the private keys used for signing
* `-o bgpsec-updates.bin` is the output file storing the resulting BGPsec updates in binary format
* `-m 10` defines a maximum of 10 generated updates. If no value is given, the entire input dump is processed
