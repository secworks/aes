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
AES_192_ROUNDS = 12
AES_256_ROUNDS = 14

AES_ENCIPHER = 1
AES_DECIPHER = 0

AES_128_BIT_KEY = 0
AES_192_BIT_KEY = 1
AES_256_BIT_KEY = 2


#-------------------------------------------------------------------
# ChaCha()
#-------------------------------------------------------------------
class AES():
    rounds = [10, 12, 14]

    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
            0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
            0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
            0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
            0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
            0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
            0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
            0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
            0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
            0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]


    def __init__(self, verbose = 0):
        self.verbose = verbose
        self.round_keys = [0] * AES_256_ROUNDS

        
    def init(self, key, keylen):
        self.key = key
        self.keylen = keylen
        _gen_roundkeys()
        

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
        self.rcon = 0x8d

        for i in range(256):
            print("rcon[0x%02x] = 0x%02x" % (i, self.rcon))
            self.rcon = ((self.rcon << 1) ^ (0x11b & -(self.rcon >> 7))) & 0xff

            #self.roundkeys = [0] * rounds[self.keylen]


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
        

def test_key_expansion():
    my_aes = AES()
    my_aes._gen_roundkeys()

    
#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the AES Python model started")
    print("====================================")
    print

    # Test the key expansion.
    test_key_expansion()

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
