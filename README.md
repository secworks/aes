aes
======

Verilog implementation of the symmetric block cipher AES (Advanced
Encryption Standard) as specified in the NIST document [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).



## Introduction ##

This implementation supports 128 , 192and 256 bit keys. The
implementation is iterative but process all bytes in parallel and with
16 S-boxes in the data path.

The encipher and decipher round functionality are separated, but the
state, key expansion anc control is common. This makes it possible to
hard wire either encipher or decipher and allow the build tools to
optimize away the other functionality which will reduce the size to
about 50%. For cipher modes such as CTR, GCM decryption in the AES core
will never be used.



## Status ##

***(2014-04-26)***

Most of the RTL completed but not yet debugged. The key expansion is
still lacking. The architecture has been reworked several times, but
this one looks promising.


***(2014-03-19)***

Several commits done up to this date. Halfway there.
Changed name of repo to simply 'aes' to reflect that we will support at
least both 128 and 256 bit keys. Possibly also 192 albeit nobody uses it
(afaik).


***(2014-02-21***:
Initial commit. Nothing really here yet.

