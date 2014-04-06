#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# aes512.py
# ---------
# Simple, pure Python model of the AES block cipher. The model is
# used as a reference for the HW implementation. The code follows
# the structure of the HW implementation as much as possible.
#
#
# Author: Joachim Strömbergson
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
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys


#-------------------------------------------------------------------
# Constants.
#-------------------------------------------------------------------
AES_128_ROUNDS = 10
AES_128_ROUNDS = 12
AES_128_ROUNDS = 14


#-------------------------------------------------------------------
# ChaCha()
#-------------------------------------------------------------------
class AES():
    def __init__(self, verbose = 0):
        self.verbose = verbose
        self.NUM_ROUNDS = 80

        
    def init(self, key, keylen):
        pass
        

    def next(self, block):
        result = [8] * 16
        return result


    def _initial_round(self):
        pass

    def _aes_round(self):
        pass

    def _final_round(self):
        pass
    
    
    def _gen_roundkeys(self):
        pass


    def _print_state(self, round):
        print("State at round 0x%02x:" % round)
        print("")



#-------------------------------------------------------------------
# compare_blocks()
#
# Compare an AES block and print results.
#-------------------------------------------------------------------
def compare_blocks(block, expected):
    if (block != expected):
        print("Error:")
        print("Got:")
        print(block)
        print("Expected:")
        print(expected)
    else:
        print("Test case ok.")


#-------------------------------------------------------------------
# test_NISR_ecb_single_block()
#
# Perform single block ECB mode testing as specified by NIST:
# http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
#-------------------------------------------------------------------
def test_NISR_ecb_single_block():
    my_aes = AES()
    pass
        
    
#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the AES Python model started")
    print("====================================")
    print

    test_NISR_ecb_single_block()
    
    print
    print("Testing the AES Python model completed")
    print("======================================")


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF aes.py
#=======================================================================
