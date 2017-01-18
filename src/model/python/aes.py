#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# aes.py
# ------
# Simple, pure Python, word based model of the AES cipher with
# support for 128 and 256 bit keys.
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
VERBOSE = True
DUMP_VARS = True

AES_128_ROUNDS = 10
AES_256_ROUNDS = 14


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


inv_sbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
            0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
            0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
            0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
            0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
            0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
            0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
            0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
            0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
            0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
            0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
            0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
            0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
            0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
            0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
            0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


#-------------------------------------------------------------------
# check_block()
#
# Check and report if a result block matches expected block.
#-------------------------------------------------------------------
def check_block(expected, result):
    if (expected[0] == result[0]) and  (expected[1] == result[1]) and\
         (expected[2] == result[2]) and  (expected[3] == result[3]):
        print("OK. Result matches expected.")
        print("")
        return 0

    else:
        print("ERROR. Result does not match expected.")
        print("Expected:")
        print_block(expected)
        print("Got:")
        print_block(result)
        print("")
        return 1


#-------------------------------------------------------------------
# print_bytekeys()
#
# Print a set of round keys given as an array of bytes.
#-------------------------------------------------------------------
def print_bytekeys(keys):
    i = 0
    print("Number of round keys: %d" % (int(len(keys) / 16)))
    while i < (len(keys) - 1):
        for j in range(16):
            print("0x%02x " % keys[i + j], end="")
        print("")
        i += 16

#-------------------------------------------------------------------
# print_block()
#
# Print the given block as four 32 bit words.
#-------------------------------------------------------------------
def print_block(block):
    (w0, w1, w2, w3) = block
    print("0x%08x, 0x%08x, 0x%08x, 0x%08x" % (w0, w1, w2, w3))


#-------------------------------------------------------------------
# print_key()
#
# Print the given key as on or two sets of four 32 bit words.
#-------------------------------------------------------------------
def print_key(key):
    if len(key) == 8:
        (k0, k1, k2, k3, k4, k5, k6, k7) = key
        print_block((k0, k1, k2, k3))
        print_block((k4, k5, k6, k7))
    else:
        print_block(key)


#-------------------------------------------------------------------
# b2w()
#
# Create a word from the given bytes.
#-------------------------------------------------------------------
def b2w(b0, b1, b2, b3):
    return (b0 << 24) + (b1 << 16) + (b2 << 8) + b3


#-------------------------------------------------------------------
# w2b()
#
# Extracts the bytes in a word.
#-------------------------------------------------------------------
def w2b(w):
    b0 = w >> 24
    b1 = w >> 16 & 0xff
    b2 = w >> 8 & 0xff
    b3 = w & 0xff

    return (b0, b1, b2, b3)


#-------------------------------------------------------------------
# gm2()
#
# The specific Galois Multiplication by two for a given byte.
#-------------------------------------------------------------------
def gm2(b):
    return ((b << 1) ^ (0x1b & ((b >> 7) * 0xff))) & 0xff


#-------------------------------------------------------------------
# gm3()
#
# The specific Galois Multiplication by three for a given byte.
#-------------------------------------------------------------------
def gm3(b):
    return gm2(b) ^ b


#-------------------------------------------------------------------
# gm4()
#
# The specific Galois Multiplication by four for a given byte.
#-------------------------------------------------------------------
def gm4(b):
    return gm2(gm2(b))


#-------------------------------------------------------------------
# gm8()
#
# The specific Galois Multiplication by eight for a given byte.
#-------------------------------------------------------------------
def gm8(b):
    return gm2(gm4(b))


#-------------------------------------------------------------------
# gm09()
#
# The specific Galois Multiplication by nine for a given byte.
#-------------------------------------------------------------------
def gm09(b):
    return gm8(b) ^ b


#-------------------------------------------------------------------
# gm11()
#
# The specific Galois Multiplication by 11 for a given byte.
#-------------------------------------------------------------------
def gm11(b):
    return gm8(b) ^ gm2(b) ^ b


#-------------------------------------------------------------------
# gm13()
#
# The specific Galois Multiplication by 13 for a given byte.
#-------------------------------------------------------------------
def gm13(b):
    return gm8(b) ^ gm4(b) ^ b


#-------------------------------------------------------------------
# gm14()
#
# The specific Galois Multiplication by 14 for a given byte.
#-------------------------------------------------------------------
def gm14(b):
    return gm8(b) ^ gm4(b) ^ gm2(b)


#-------------------------------------------------------------------
# substw()
#
# Returns a 32-bit word in which each of the bytes in the
# given 32-bit word has been used as lookup into the AES S-box.
#-------------------------------------------------------------------
def substw(w):
    (b0, b1, b2, b3) = w2b(w)

    s0 = sbox[b0]
    s1 = sbox[b1]
    s2 = sbox[b2]
    s3 = sbox[b3]

    res = b2w(s0, s1, s2, s3)

    if VERBOSE:
        print("Inside substw:")
        print("b0 = 0x%02x, b1 = 0x%02x, b2 = 0x%02x, b3 = 0x%02x" %
              (b0, b1, b2, b3))
        print("s0 = 0x%02x, s1 = 0x%02x, s2 = 0x%02x, s3 = 0x%02x" %
              (s0, s1, s2, s3))
        print("res = 0x%08x" % (res))

    return res


#-------------------------------------------------------------------
# inv_substw()
#
# Returns a 32-bit word in which each of the bytes in the
# given 32-bit word has been used as lookup into
# the inverse AES S-box.
#-------------------------------------------------------------------
def inv_substw(w):
    (b0, b1, b2, b3) = w2b(w)

    s0 = inv_sbox[b0]
    s1 = inv_sbox[b1]
    s2 = inv_sbox[b2]
    s3 = inv_sbox[b3]

    res = b2w(s0, s1, s2, s3)

    if VERBOSE:
        print("Inside inv_substw:")
        print("b0 = 0x%02x, b1 = 0x%02x, b2 = 0x%02x, b3 = 0x%02x" %
              (b0, b1, b2, b3))
        print("s0 = 0x%02x, s1 = 0x%02x, s2 = 0x%02x, s3 = 0x%02x" %
              (s0, s1, s2, s3))
        print("res = 0x%08x" % (res))

    return res


#-------------------------------------------------------------------
# rolx()
#
# Rotate the given 32 bit word x bits left.
#-------------------------------------------------------------------
def rolx(w, x):
    return ((w << x) | (w >> (32 - x))) & 0xffffffff


#-------------------------------------------------------------------
# next_128bit_key()
#
# Generate the next four key words for aes-128 based on given
# rcon and previous key words.
#-------------------------------------------------------------------
def next_128bit_key(prev_key, rcon):
    (w0, w1, w2, w3) = prev_key

    rol = rolx(w3, 8)
    subst = substw(rol)
    t = subst ^ (rcon << 24)

    k0 = w0 ^ t
    k1 = w1 ^ w0 ^ t
    k2 = w2 ^ w1 ^ w0 ^ t
    k3 = w3 ^ w2 ^ w1 ^ w0 ^ t

    if VERBOSE:
        print("Inside next 128bit key:")
        print("w0 = 0x%08x, w1 = 0x%08x, w2 = 0x%08x, w3 = 0x%08x" %
              (w0, w1, w2, w3))
        print("rol = 0x%08x, subst = 0x%08x, rcon = 0x%02x, t = 0x%08x" %
              (rol, subst, rcon, t))
        print("k0 = 0x%08x, k1 = 0x%08x, k2 = 0x%08x, k3 = 0x%08x" %
              (k0, k1, k2, k3))

    return (k0, k1, k2, k3)


#-------------------------------------------------------------------
# key_gen128()
#
# Generating the keys for 128 bit keys.
#-------------------------------------------------------------------
def key_gen128(key):
    print("Doing the 128 bit key expansion")

    round_keys = []

    round_keys.append(key)

    for i in range(10):
        round_keys.append(next_128bit_key(round_keys[i], get_rcon(i + 1)))

    if VERBOSE:
        print("Input key:")
        print_block(key)
        print("")

        print("Generated keys:")
        for k in round_keys:
            print_block(k)
        print("")

    return round_keys


#-------------------------------------------------------------------
# next_256bit_key_a()
#
# Generate the next four key words for aes-256 using algorithm A
# based on given rcon and the previous two keys.
#-------------------------------------------------------------------
def next_256it_key_a(key0, key1, rcon):
    (w0, w1, w2, w3) = key0
    (w4, w5, w6, w7) = key1

    sw = substw(rolx(w7, 8))
    rw = (rcon << 24)
    t = sw ^ rw

    k0 = w0 ^ t
    k1 = w1 ^ w0 ^ t
    k2 = w2 ^ w1 ^ w0 ^ t
    k3 = w3 ^ w2 ^ w1 ^ w0 ^ t

    if (DUMP_VARS):
        print("next_256bit_key_a:")
        print("w0 = 0x%08x, w0 = 0x%08x, w0 = 0x%08x, w0 = 0x%08x" % (w0, w1, w2, w3))
        print("w4 = 0x%08x, w5 = 0x%08x, w6 = 0x%08x, w7 = 0x%08x" % (w4, w5, w6, w7))
        print("t = 0x%08x, sw = 0x%08x, rw = 0x%08x" % (t, sw, rw))
        print("k0 = 0x%08x, k0 = 0x%08x, k0 = 0x%08x, k0 = 0x%08x" % (k0, k1, k2, k3))
        print("")

    return (k0, k1, k2, k3)


#-------------------------------------------------------------------
# next_256bit_key_b()
#
# Generate the next four key words for aes-256 using algorithm B
# based on given previous eight keywords.
#-------------------------------------------------------------------
def next_256it_key_b(key0, key1):
    (w0, w1, w2, w3) = key0
    (w4, w5, w6, w7) = key1

    t = substw(w7)

    k0 = w0 ^ t
    k1 = w1 ^ w0 ^ t
    k2 = w2 ^ w1 ^ w0 ^ t
    k3 = w3 ^ w2 ^ w1 ^ w0 ^ t

    if (DUMP_VARS):
        print("next_256bit_key_b:")
        print("w0 = 0x%08x, w0 = 0x%08x, w0 = 0x%08x, w0 = 0x%08x" % (w0, w1, w2, w3))
        print("w4 = 0x%08x, w5 = 0x%08x, w6 = 0x%08x, w7 = 0x%08x" % (w4, w5, w6, w7))
        print("t = 0x%08x" % (t))
        print("k0 = 0x%08x, k0 = 0x%08x, k0 = 0x%08x, k0 = 0x%08x" % (k0, k1, k2, k3))
        print("")

    return (k0, k1, k2, k3)


#-------------------------------------------------------------------
# key_gen256()
#
# Generating the keys for 256 bit keys.
#-------------------------------------------------------------------
def key_gen256(key):
    round_keys = []
    (k0, k1, k2, k3, k4, k5, k6, k7) = key

    round_keys.append((k0, k1, k2, k3))
    round_keys.append((k4, k5, k6, k7))

    j = 1
    for i in range(0, (AES_256_ROUNDS - 2), 2):
        k = next_256it_key_a(round_keys[i], round_keys[i + 1], get_rcon(j))
        round_keys.append(k)
        k = next_256it_key_b(round_keys[i + 1], round_keys[i + 2])
        round_keys.append(k)
        j += 1

    # One final key needs to be generated.
    k = next_256it_key_a(round_keys[12], round_keys[13], get_rcon(7))
    round_keys.append(k)

    if VERBOSE:
        print("Input key:")
        print_block((k0, k1, k2, k3))
        print_block((k4, k5, k6, k7))
        print("")

        print("Generated keys:")
        for k in round_keys:
            print_block(k)
        print("")

    return round_keys


#-------------------------------------------------------------------
# get_rcon()
#
# Function implementation of rcon. Calculates rcon for a
# given round. This could be implemented as an iterator.
#-------------------------------------------------------------------
def get_rcon(round):
    rcon = 0x8d

    for i in range(0, round):
        rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7))) & 0xff

    return rcon


#-------------------------------------------------------------------
# addroundkey()
#
# AES AddRoundKey block operation.
# Perform XOR combination of the given block and the given key.
#-------------------------------------------------------------------
def addroundkey(key, block):
    (w0, w1, w2, w3) = block
    (k0, k1, k2, k3) = key

    res_block = (w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3)

    if VERBOSE:
        print("AddRoundKey key, block in and block out:")
        print_block(key)
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# mixw()
#
# Perform bit mixing of the given words.
#-------------------------------------------------------------------
def mixw(w):
    (b0, b1, b2, b3) = w2b(w)

    mb0 = gm2(b0) ^ gm3(b1) ^ b2      ^ b3
    mb1 = b0      ^ gm2(b1) ^ gm3(b2) ^ b3
    mb2 = b0      ^ b1      ^ gm2(b2) ^ gm3(b3)
    mb3 = gm3(b0) ^ b1      ^ b2      ^ gm2(b3)

    return b2w(mb0, mb1, mb2, mb3)


#-------------------------------------------------------------------
# mixcolumns()
#
# AES MixColumns on the given block.
#-------------------------------------------------------------------
def mixcolumns(block):
    (c0, c1, c2, c3) = block

    mc0 = mixw(c0)
    mc1 = mixw(c1)
    mc2 = mixw(c2)
    mc3 = mixw(c3)

    res_block = (mc0, mc1, mc2, mc3)

    if VERBOSE:
        print("MixColumns block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# subbytes()
#
# AES SubBytes operation on the given block.
#-------------------------------------------------------------------
def subbytes(block):
    (w0, w1, w2, w3) = block

    res_block = (substw(w0), substw(w1), substw(w2), substw(w3))

    if VERBOSE:
        print("SubBytes block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# shiftrows()
#
# AES ShiftRows block operation.
#-------------------------------------------------------------------
def shiftrows(block):
    (w0, w1, w2, w3) = block

    c0 = w2b(w0)
    c1 = w2b(w1)
    c2 = w2b(w2)
    c3 = w2b(w3)

    ws0 = b2w(c0[0], c1[1],  c2[2],  c3[3])
    ws1 = b2w(c1[0], c2[1],  c3[2],  c0[3])
    ws2 = b2w(c2[0], c3[1],  c0[2],  c1[3])
    ws3 = b2w(c3[0], c0[1],  c1[2],  c2[3])

    res_block = (ws0, ws1, ws2, ws3)

    if VERBOSE:
        print("ShiftRows block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# aes_encipher()
#
# Perform AES encipher operation for the given block using the
# given key length.
#-------------------------------------------------------------------
def aes_encipher_block(key, block):
    tmp_block = block[:]

    # Get round keys based on the given key.
    if len(key) == 4:
        round_keys = key_gen128(key)
        num_rounds = AES_128_ROUNDS
    else:
        round_keys = key_gen256(key)
        num_rounds = AES_256_ROUNDS

    # Init round
    print("  Initial AddRoundKeys round.")
    tmp_block4 = addroundkey(round_keys[0], block)

    # Main rounds
    for i in range(1 , (num_rounds)):
        print("")
        print("  Round %02d" % i)
        print("  ---------")

        tmp_block1 = subbytes(tmp_block4)
        tmp_block2 = shiftrows(tmp_block1)
        tmp_block3 = mixcolumns(tmp_block2)
        tmp_block4 = addroundkey(round_keys[i], tmp_block3)


    # Final round
    print("  Final round.")
    tmp_block1 = subbytes(tmp_block4)
    tmp_block2 = shiftrows(tmp_block1)
    tmp_block3 = addroundkey(round_keys[num_rounds], tmp_block2)

    return tmp_block3


#-------------------------------------------------------------------
# inv_mixw()
#
# Perform inverse bit mixing of the given words.
#-------------------------------------------------------------------
def inv_mixw(w):
    (b0, b1, b2, b3) = w2b(w)

    mb0 = gm14(b0) ^ gm11(b1) ^ gm13(b2) ^ gm09(b3)
    mb1 = gm09(b0) ^ gm14(b1) ^ gm11(b2) ^ gm13(b3)
    mb2 = gm13(b0) ^ gm09(b1) ^ gm14(b2) ^ gm11(b3)
    mb3 = gm11(b0) ^ gm13(b1) ^ gm09(b2) ^ gm14(b3)

    return b2w(mb0, mb1, mb2, mb3)


#-------------------------------------------------------------------
# inv_mixcolumns()
#
# AES Inverse MixColumns on the given block.
#-------------------------------------------------------------------
def inv_mixcolumns(block):
    (c0, c1, c2, c3) = block

    mc0 = inv_mixw(c0)
    mc1 = inv_mixw(c1)
    mc2 = inv_mixw(c2)
    mc3 = inv_mixw(c3)

    res_block = (mc0, mc1, mc2, mc3)

    if VERBOSE:
        print("Inverse MixColumns block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# inv_shiftrows()
#
# AES inverse ShiftRows block operation.
#-------------------------------------------------------------------
def inv_shiftrows(block):
    (w0, w1, w2, w3) = block

    c0 = w2b(w0)
    c1 = w2b(w1)
    c2 = w2b(w2)
    c3 = w2b(w3)

    ws0 = b2w(c0[0], c3[1],  c2[2],  c1[3])
    ws1 = b2w(c1[0], c0[1],  c3[2],  c2[3])
    ws2 = b2w(c2[0], c1[1],  c0[2],  c3[3])
    ws3 = b2w(c3[0], c2[1],  c1[2],  c0[3])

    res_block = (ws0, ws1, ws2, ws3)

    if VERBOSE:
        print("Inverse ShiftRows block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# inv_subbytes()
#
# AES inverse SubBytes operation on the given block.
#-------------------------------------------------------------------
def inv_subbytes(block):
    (w0, w1, w2, w3) = block

    res_block = (inv_substw(w0), inv_substw(w1), inv_substw(w2), inv_substw(w3))

    if VERBOSE:
        print("Inverse SubBytes block in and block out:")
        print_block(block)
        print_block(res_block)
        print("")

    return res_block


#-------------------------------------------------------------------
# aes_decipher()
#
# Perform AES decipher operation for the given block
# using the given key length.
#-------------------------------------------------------------------
def aes_decipher_block(key, block):
    tmp_block = block[:]

    # Get round keys based on the given key.
    if len(key) == 4:
        round_keys = key_gen128(key)
        num_rounds = AES_128_ROUNDS
    else:
        round_keys = key_gen256(key)
        num_rounds = AES_256_ROUNDS

    # Initial round
    print("  Initial, partial round.")
    tmp_block1 = addroundkey(round_keys[len(round_keys) - 1], tmp_block)
    tmp_block2 = inv_shiftrows(tmp_block1)
    tmp_block4 = inv_subbytes(tmp_block2)

    # Main rounds
    for i in range(1 , (num_rounds)):
        print("")
        print("  Round %02d" % i)
        print("  ---------")

        tmp_block1 = addroundkey(round_keys[(len(round_keys) - i - 1)], tmp_block4)
        tmp_block2 = inv_mixcolumns(tmp_block1)
        tmp_block3 = inv_shiftrows(tmp_block2)
        tmp_block4 = inv_subbytes(tmp_block3)

    # Final round
    print("  Final AddRoundKeys round.")
    res_block = addroundkey(round_keys[0], tmp_block4)

    return res_block


#-------------------------------------------------------------------
# test_mixcolumns()
#
# Test the mixcolumns and inverse mixcolumns operations using
# some simple test values.
#-------------------------------------------------------------------
def test_mixcolumns():
    nist_aes128_key = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)

    print("Test of mixcolumns and inverse mixcolumns:")
    mixresult = mixcolumns(nist_aes128_key)
    inv_mixresult = inv_mixcolumns(mixresult)

    print("Test of mixw ochi inv_mixw:")
    testw = 0xdb135345
    expw  = 0x8e4da1bc
    mixresult = mixw(testw)
    inv_mixresult = inv_mixw(mixresult)
    print("Testword:   0x%08x" % testw)
    print("expexted:   0x%08x" % expw)
    print("mixword:    0x%08x" % mixresult)
    print("invmixword: 0x%08x" % inv_mixresult)


#-------------------------------------------------------------------
# test_aes()
#
# Test the AES implementation with 128 and 256 bit keys.
#-------------------------------------------------------------------
def test_aes():
    nist_aes128_key = (0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c)
    nist_aes256_key = (0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                       0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4)

    nist_plaintext0 = (0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a)
    nist_plaintext1 = (0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51)
    nist_plaintext2 = (0x30c81c46, 0xa35ce411, 0xe5fbc119, 0x1a0a52ef)
    nist_plaintext3 = (0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710)

    nist_exp128_0 = (0x3ad77bb4, 0x0d7a3660, 0xa89ecaf3, 0x2466ef97)
    nist_exp128_1 = (0xf5d3d585, 0x03b9699d, 0xe785895a, 0x96fdbaaf)
    nist_exp128_2 = (0x43b1cd7f, 0x598ece23, 0x881b00e3, 0xed030688)
    nist_exp128_3 = (0x7b0c785e, 0x27e8ad3f, 0x82232071, 0x04725dd4)

    nist_exp256_0 = (0xf3eed1bd, 0xb5d2a03c, 0x064b5a7e, 0x3db181f8)
    nist_exp256_1 = (0x591ccb10, 0xd410ed26, 0xdc5ba74a, 0x31362870)
    nist_exp256_2 = (0xb6ed21b9, 0x9ca6f4f9, 0xf153e7b1, 0xbeafed1d)
    nist_exp256_3 = (0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7)


    print("Doing block encryption.")
    enc_result128_0 = aes_encipher_block(nist_aes128_key, nist_plaintext0)
    enc_result128_1 = aes_encipher_block(nist_aes128_key, nist_plaintext1)
    enc_result128_2 = aes_encipher_block(nist_aes128_key, nist_plaintext2)
    enc_result128_3 = aes_encipher_block(nist_aes128_key, nist_plaintext3)

    enc_result256_0 = aes_encipher_block(nist_aes256_key, nist_plaintext0)
    enc_result256_1 = aes_encipher_block(nist_aes256_key, nist_plaintext1)
    enc_result256_2 = aes_encipher_block(nist_aes256_key, nist_plaintext2)
    enc_result256_3 = aes_encipher_block(nist_aes256_key, nist_plaintext3)

    print("Doing block decryption.")
    dec_result128_0 = aes_decipher_block(nist_aes128_key, nist_exp128_0)
    dec_result128_1 = aes_decipher_block(nist_aes128_key, nist_exp128_1)
    dec_result128_2 = aes_decipher_block(nist_aes128_key, nist_exp128_2)
    dec_result128_3 = aes_decipher_block(nist_aes128_key, nist_exp128_3)

    dec_result256_0 = aes_decipher_block(nist_aes256_key, nist_exp256_0)
    dec_result256_1 = aes_decipher_block(nist_aes256_key, nist_exp256_1)
    dec_result256_2 = aes_decipher_block(nist_aes256_key, nist_exp256_2)
    dec_result256_3 = aes_decipher_block(nist_aes256_key, nist_exp256_3)

    tc_errors = 0
    tc        = 0

    if VERBOSE:
        print("   AES Encipher tests")
        print("   ==================")

        print("Test 0 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_plaintext0)
        tc_errors += check_block(nist_exp128_0, enc_result128_0)
        tc += 1

        print("Test 1 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_plaintext1)
        tc_errors += check_block(nist_exp128_1, enc_result128_1)
        tc += 1

        print("Test 2 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_plaintext2)
        tc_errors += check_block(nist_exp128_2, enc_result128_2)
        tc += 1

        print("Test 3 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_plaintext3)
        tc_errors += check_block(nist_exp128_3, enc_result128_3)
        tc += 1

        print("Test 0 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_plaintext0)
        tc_errors += check_block(nist_exp256_0, enc_result256_0)
        tc += 1

        print("Test 1 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_plaintext1)
        tc_errors += check_block(nist_exp256_1, enc_result256_1)
        tc += 1

        print("Test 2 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_plaintext2)
        tc_errors += check_block(nist_exp256_2, enc_result256_2)
        tc += 1

        print("Test 3 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_plaintext3)
        tc_errors += check_block(nist_exp256_3, enc_result256_3)
        tc += 1


        print("")
        print("   AES Decipher tests")
        print("   ==================")

        print("Test 0 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_exp128_0)
        tc_errors += check_block(nist_plaintext0, dec_result128_0)
        tc += 1

        print("Test 1 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_exp128_1)
        tc_errors += check_block(nist_plaintext1, dec_result128_1)
        tc += 1

        print("Test 2 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_exp128_2)
        tc_errors += check_block(nist_plaintext2, dec_result128_2)
        tc += 1

        print("Test 3 for AES-128.")
        print("Key:")
        print_key(nist_aes128_key)
        print("Block in:")
        print_block(nist_exp128_3)
        tc_errors += check_block(nist_plaintext3, dec_result128_3)
        tc += 1

        print("Test 0 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_exp256_0)
        tc_errors += check_block(nist_plaintext0, dec_result256_0)
        tc += 1

        print("Test 1 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_exp256_1)
        tc_errors += check_block(nist_plaintext1, dec_result256_1)
        tc += 1

        print("Test 2 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_exp256_2)
        tc_errors += check_block(nist_plaintext2, dec_result256_2)
        tc += 1

        print("Test 3 for AES-256.")
        print("Key:")
        print_key(nist_aes256_key)
        print("Block in:")
        print_block(nist_exp256_3)
        tc_errors += check_block(nist_plaintext3, dec_result256_3)
        tc += 1

        print("Number of test cases executed: %d" % tc)
        if (tc_errors == 0):
            print("All test cases OK.")
        else:
            print("Number of failing test cases: %d" % tc_errors)


#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the AES cipher model")
    print("============================")
    print

    # test_mixcolumns()
    test_aes()


#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__":
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF aes_key_gen.py
#=======================================================================
