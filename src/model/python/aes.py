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

AES_ENCIPHER = 1
AES_DECIPHER = 0

AES_128_BIT_KEY = 0
AES_192_BIT_KEY = 1
AES_256_BIT_KEY = 2


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
# test_NIST_ecb_single_block()
#
# Perform single block ECB mode testing as specified by NIST:
# http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
#-------------------------------------------------------------------
def test_nist_ecb_single_block(tc, encdec, key, keylen, plaintext, expected):
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

    nist_aes128_key = 0x2b7e151628aed2a6abf7158809cf4f3c
    nist_aes192_key = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    nist_aes256_key = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    
    nist_plaintext0 = 0x6bc1bee22e409f96e93d7e117393172a
    nist_plaintext1 = 0xae2d8a571e03ac9c9eb76fac45af8e51
    nist_plaintext2 = 0x30c81c46a35ce411e5fbc1191a0a52ef
    nist_plaintext3 = 0xf69f2445df4f9b17ad2b417be66c3710

    nist_ecb_128_enc_expected0 = 0x3ad77bb40d7a3660a89ecaf32466ef97
    nist_ecb_128_enc_expected1 = 0xf5d3d58503b9699de785895a96fdbaaf
    nist_ecb_128_enc_expected2 = 0x43b1cd7f598ece23881b00e3ed030688
    nist_ecb_128_enc_expected3 = 0x7b0c785e27e8ad3f8223207104725dd4

    nist_ecb_192_enc_expected0 = 0xbd334f1d6e45f25ff712a214571fa5cc
    nist_ecb_192_enc_expected1 = 0x974104846d0ad3ad7734ecb3ecee4eef
    nist_ecb_192_enc_expected2 = 0xef7afd2270e2e60adce0ba2face6444e
    nist_ecb_192_enc_expected3 = 0x9a4b41ba738d6c72fb16691603c18e0e
    
    nist_ecb_256_enc_expected0 = 0xf3eed1bdb5d2a03c064b5a7e3db181f8
    nist_ecb_256_enc_expected1 = 0x591ccb10d410ed26dc5ba74a31362870
    nist_ecb_256_enc_expected2 = 0xb6ed21b99ca6f4f9f153e7b1beafed1d
    nist_ecb_256_enc_expected3 = 0x23304b7a39f9f3ff067d8d8f9e24ecc7

    print("ECB 128 bit key tests")
    print("---------------------")
    
    test_nist_ecb_single_block(1, AES_ENCIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_plaintext0, nist_ecb_128_enc_expected0)

    test_nist_ecb_single_block(2, AES_ENCIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_plaintext1, nist_ecb_128_enc_expected1)

    test_nist_ecb_single_block(3, AES_ENCIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_plaintext2, nist_ecb_128_enc_expected2)
    
    test_nist_ecb_single_block(3, AES_ENCIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_plaintext3, nist_ecb_128_enc_expected3)

    
    test_nist_ecb_single_block(5, AES_DECIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_ecb_128_enc_expected0, nist_plaintext0)
    
    test_nist_ecb_single_block(6, AES_DECIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_ecb_128_enc_expected1, nist_plaintext1)

    test_nist_ecb_single_block(7, AES_DECIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_ecb_128_enc_expected2, nist_plaintext2)

    test_nist_ecb_single_block(8, AES_DECIPHER, nist_aes128_key, AES_128_BIT_KEY, 
                               nist_ecb_128_enc_expected3, nist_plaintext3)
    

    print("")
    print("ECB 192 bit key tests")
    print("---------------------")
    
    test_nist_ecb_single_block(9, AES_ENCIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_plaintext0, nist_ecb_192_enc_expected0)
    
    test_nist_ecb_single_block(10, AES_ENCIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_plaintext1, nist_ecb_192_enc_expected1)
    
    test_nist_ecb_single_block(11, AES_ENCIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_plaintext2, nist_ecb_192_enc_expected2)

    test_nist_ecb_single_block(12, AES_ENCIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_plaintext3, nist_ecb_192_enc_expected3)

      
    test_nist_ecb_single_block(13, AES_DECIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_ecb_192_enc_expected0, nist_plaintext0)

    test_nist_ecb_single_block(14, AES_DECIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_ecb_192_enc_expected1, nist_plaintext1)

    test_nist_ecb_single_block(15, AES_DECIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_ecb_192_enc_expected2, nist_plaintext2)

    test_nist_ecb_single_block(16, AES_DECIPHER, nist_aes192_key, AES_192_BIT_KEY, 
                               nist_ecb_192_enc_expected3, nist_plaintext3)


      
    print("")
    print("ECB 256 bit key tests")
    print("---------------------")
    test_nist_ecb_single_block(17, AES_ENCIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_plaintext0, nist_ecb_256_enc_expected0)

    test_nist_ecb_single_block(18, AES_ENCIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_plaintext1, nist_ecb_256_enc_expected1)
      
    test_nist_ecb_single_block(19, AES_ENCIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_plaintext2, nist_ecb_256_enc_expected2)

    test_nist_ecb_single_block(20, AES_ENCIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_plaintext3, nist_ecb_256_enc_expected3)
      
      
    test_nist_ecb_single_block(21, AES_DECIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_ecb_256_enc_expected0, nist_plaintext0)

    test_nist_ecb_single_block(22, AES_DECIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_ecb_256_enc_expected1, nist_plaintext1)
      
    test_nist_ecb_single_block(23, AES_DECIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_ecb_256_enc_expected2, nist_plaintext2)

    test_nist_ecb_single_block(24, AES_DECIPHER, nist_aes256_key, AES_256_BIT_KEY, 
                               nist_ecb_256_enc_expected3, nist_plaintext3)
    
    print("")
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
