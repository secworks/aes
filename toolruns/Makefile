#===================================================================
#
# Makefile
# --------
# Makefile for building the aes keygen, core and top simulations.
#
#
# Author: Joachim Strombergson
# Copyright (c) 2014, Secworks Sweden AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#===================================================================

SBOX_SRC=../src/rtl/aes_sbox.v
INV_SBOX_SRC=../src/rtl/aes_inv_sbox.v
KEYMEM_SRC=../src/rtl/aes_key_mem.v
ENCIPHER_SRC=../src/rtl/aes_encipher_block.v
DECIPHER_SRC=../src/rtl/aes_decipher_block.v
CORE_SRC=../src/rtl/aes_core.v $(KEYMEM_SRC) $(SBOX_SRC) $(INV_SBOX_SRC) $(ENCIPHER_SRC) $(DECIPHER_SRC)
TOP_SRC=../src/rtl/aes.v $(CORE_SRC)

TB_TOP_SRC =../src/tb/tb_aes.v
TB_CORE_SRC =../src/tb/tb_aes_core.v
TB_KEYMEM_SRC =../src/tb/tb_aes_key_mem.v
TB_ENCIPHER_SRC =../src/tb/tb_aes_encipher_block.v
TB_DECIPHER_SRC =../src/tb/tb_aes_decipher_block.v

CC = iverilog
CC_FLAGS = -Wall

LINT = verilator
LINT_FLAGS = +1364-2001ext+ --lint-only  -Wall -Wno-fatal -Wno-DECLFILENAME


all: top.sim core.sim keymem.sim encipher.sim decipher.sim

top.sim: $(TB_TOP_SRC) $(TOP_SRC)
	$(CC) $(CC_FLAGS) -o top.sim $(TB_TOP_SRC) $(TOP_SRC)


core.sim: $(TB_CORE_SRC) $(CORE_SRC)
	$(CC) $(CC_FLAGS) -o core.sim $(TB_CORE_SRC) $(CORE_SRC)


keymem.sim:  $(TB_KEYMEM_SRC) $(KEYMEM_SRC) $(SBOX_SRC)
	$(CC) $(CC_FLAGS) -o keymem.sim $(TB_KEYMEM_SRC) $(KEYMEM_SRC) $(SBOX_SRC)


encipher.sim:  $(TB_ENCIPHER_SRC) $(ENCIPHER_SRC) $(SBOX_SRC)
	$(CC) $(CC_FLAGS) -o encipher.sim $(TB_ENCIPHER_SRC) $(ENCIPHER_SRC) $(SBOX_SRC)


decipher.sim:  $(TB_DECIPHER_SRC) $(DECIPHER_SRC) $(INV_SBOX_SRC)
	$(CC) $(CC_FLAGS) -o decipher.sim $(TB_DECIPHER_SRC) $(DECIPHER_SRC) $(INV_SBOX_SRC)


sim-keymem: keymem.sim
	./keymem.sim


sim-encipher: encipher.sim
	./encipher.sim


sim-decipher: decipher.sim
	./decipher.sim


sim-core: core.sim
	./core.sim


sim-top: top.sim
	./top.sim


lint:  $(TOP_SRC)
	$(LINT) $(LINT_FLAGS) $(TOP_SRC)


clean:
	rm -f decipher.sim
	rm -f encipher.sim
	rm -f keymem.sim
	rm -f core.sim
	rm -f top.sim


help:
	@echo "Build system for simulation of AES Verilog core"
	@echo ""
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:          Build all simulation targets."
	@echo "top.sim:      Build top level simulation target."
	@echo "core.sim:     Build core level simulation target."
	@echo "keymem.sim:   Build key memory simulation target."
	@echo "encipher.sim: Build encipher block simulation target."
	@echo "decipher.sim: Build decipher block simulation target."
	@echo "sim-top:      Run top level simulation."
	@echo "sim-core:     Run core level simulation."
	@echo "sim-keymem    Run keymem simulation."
	@echo "sim-encipher  Run encipher block simulation."
	@echo "sim-decipher  Run decipher block simulation."
	@echo "lint:         Lint all rtl source files."
	@echo "clean:        Delete all built files."

#===================================================================
# EOF Makefile
#===================================================================
