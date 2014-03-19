aes
======

Verilog implementation of the symmetric block cipher AES (Advanced
Encryption Standard) as specified in the NIST document [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).



## Introduction ##

This implementation supports 128 and 256 bit keys. The implementation is iterative but process all bytes in parallel and with 16 S-boxes.




## Status ##

***(2014-03-19)***
Several commits done up to this date. Halway there.
Changed name of repo to simply 'aes' to reflect that we will support at
least both 128 and 256 bit keys. Possibly also 192 albeit nobody uses it
(afaik).


***(2014-02-21***:
Initial commit. Nothing really here yet.

