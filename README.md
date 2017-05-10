aes
======

Verilog implementation of the symmetric block cipher AES (Advanced
Encryption Standard) as specified in the NIST document [FIPS 197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).


## Introduction ##

This implementation supports 128 and 256 bit keys. The
implementation is iterative and process one 128 block at a time. Blocks
are processed on a word level with 4 S-boxes in the data path. The
S-boxes for encryption are shared with the key expansion and the core
can thus not do key update in parallel with block processing.

The encipher and decipher block processing datapaths are separated and
basically self contained given access to a set of round keys and a
block. This makes it possible to hard wire either encipher or decipher
and allow the build tools to optimize away the other functionality which
will reduce the size to about 50%. For cipher modes such as CTR, GCM
decryption in the AES core will never be used and thus the decipher
block processing can be removed.

This is a fairly compact implementation. Further reduction could be
achived by just having a single S-box. Similarly the performane can be
increased by having 8 or even 16 S-boxes which would reduce the number
of cycles to two cycles for each round.


## Implementation results - ASIC ##

The core has been implemented in standard cell ASIC processes.

### TSMC 180 nm ###
Target frequency: 20 MHz
Complete flow from RTL to placed gates. Automatic clock gating and scan
insertion.

- 8 kCells
- Aera: 520 x 520 um
- Good timing margin with no big cells and buffers.


## Implementation results - FPGA ##

The core has been implemented in Altera and Xilinx FPGA devices.

### Altera Cyclone V GX ###
- 2624 ALMs
- 3123 Regs
- 96 MHz
- 46 cycles/block


### Altera Cyclone IV GX ###
- 7426 LEs
- 2994 Regs
- 96 MHz fmax
- 46 cycles/block

This means that we can do more than 2 Mblocks/s or 256 Mbps
performance.

Removing the decipher module yields:
- 5497 LEs
- 2855 Regs
- 106 MHz fmax
- 46 cycles/block


### Xilinx Spartan6LX-3 ###
- 2576 slices
- 3000 regs
- 100 MHz
- 46 cycles/block


### Xilinx Artix 7 200T-3 ###
- 2298 slices
- 2989 regs
- 97 MHz
- 46 cycles/block


## Status ##
***(2017-05-10)***

Updated with results from ASIC implementation in TSMC 180 nm process.

Removed timescale directives from testbenches which are not needed and
just makes simulation with other cores harder.


***(2017-04-13)***

Some code cleanup to make it more readable and remove warnings from some
parsers. No functional changes.

Added implementation results for Altera Cyclone V GX.


***(2016-11-20)***

__HEADSUP__
The API addresses for config and status registers has been switched. The
reason for this is all other cores provided have status on 0x09. And any
possible config on 0x0a. This change aligns the core for easier
integration, but breaks designs that uses the old version.

The core VERSION string has been updated to reflect the API change.

The core NAME has also been updated. Precviously the NAME contained
"-128", indicating that the core only supports 128 bit key length. But
the core does in fact support both 128 and 256 bit key lengths.


***(2016-09-06)***

Updated implementation results with results from Xilinx Artix-7. There
has also been done several minor fixes to shorten the code size, clarify
the implementation etc. But the functionality of the core has not been
altered. The core has been used in several designs.


***(2014-11-28)***

Top level simulation now passes all NISTs tests.


***(2014-11-26)***

Encryption and decryption now passes all NIST test cases on block level
as well as core level. The Python model can do encryption but not
decryption. The Python model contains separate tests for key generation,
mixcolumns and inverse mixcolumns.


***(2014-08-07)***

Round key generation for both AES-128 and AES-256 now works when tested
separately. Datapaths and core are yet to be debugged.


***(2014-07-27)***

Reworked the partitioning of block registers, round counters etc -
basically a rather big change. The block processing is now pretty much
self contained machines. Removed support for 192 bit keys.


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
