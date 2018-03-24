aes
===

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
block. This makes it possible to hard wire the core to only encipher or
decipher operation. This allows the synthesis/build tools to optimize
away the other functionality which will reduce the size to about
50%. This has been tested to verify that decryption is removed and the
core still works.

For cipher modes such as CTR, CCM, CMAC, GCM the decryption
functionality in the AES core will never be used and thus the decipher
block processing can be removed.

This is a fairly compact implementation. Further reduction could be
achived by just having a single S-box. Similarly the performane can be
increased by having 8 or even 16 S-boxes which would reduce the number
of cycles to two cycles for each round.


## Status ##
The core is completed, has been used in FPGAs and in ASIC. The core is
well tested and mature.


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
