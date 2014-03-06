#===================================================================
#
# Makefile
# --------
# Makefile for building the aes128 simulations.
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

WMEM_SRC=../src/rtl/sha256_w_mem.v
WMEM_TB_SRC=../src/tb/tb_sha256_w_mem.v

KEYGEN_SRC=../src/rtl/aes128_core.v ../src/rtl/aes128_keygen.v ../src/rtl/aes_sbox.v
CORE_SRC=../src/rtl/aes128_core.v ../src/rtl/aes128_keygen.v ../src/rtl/aes_sbox.v


CC=iverilog


all: core keygen


keygen: $(KEYGEN_SRC)
	$(CC) -o keygen.sim $(KEYGEN_SRC)


core: $(CORE_SRC)
	$(CC) -o core.sim $(CORE_SRC)


sim-keygen: keygen.sim
	./keygen.sim


sim-core: core.sim
	./core.sim


debug:
	@echo "No debug available."


clean:
	rm -f keygen.sim
	rm -f core.sim


help:
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:        Build all simulation targets."
	@echo "core:       Build the core simulation target."
	@echo "sim-core:   Run core level simulation."
	@echo "sim-keygen: Run core level simulation."
	@echo "debug:      Print the internal varibles."
	@echo "clean:      Delete all built files."

#===================================================================
# EOF Makefile
#===================================================================

