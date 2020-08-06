//======================================================================
//
// aes_sbox.v
// ----------
// An implementation of the AES S-box based on the work by the
// Circuit Minimization Team (CMT) at Yale:
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
//
// The specific circuit implemented is this:
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt
//
// This code is a straight mapping in of the equotions on that page.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2020, Assured AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or
// without modification, are permitted provided that the following
// conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module aes_sbox(input wire [31 : 0]  sboxw,
                output wire [31 : 0] new_sboxw
               );

  //----------------------------------------------------------------
  // Four parallel, combinational sboxes.
  //----------------------------------------------------------------
  assign new_sboxw[31 : 24] = s(sboxw[31 : 24]);
  assign new_sboxw[23 : 16] = s(sboxw[23 : 16]);
  assign new_sboxw[15 : 08] = s(sboxw[15 : 08]);
  assign new_sboxw[07 : 00] = s(sboxw[07 : 00]);


  //----------------------------------------------------------------
  // Function that implements the S-box using gates.
  //----------------------------------------------------------------
  function [0 : 7] s(input [0 : 7] u);
    begin : cmt_s
      reg [21 : 0] y;
      reg [67 : 0] t;
      reg [17 : 0] z;

      y[14] = u[03]  ^ u[05];
      y[13] = u[00]  ^ u[06];
      y[09] = u[00]  ^ u[03];
      y[08] = u[00]  ^ u[05];
      t[00] = u[01]  ^ u[02];
      y[01] = t[00]  ^ u[07];
      y[04] = y[01]  ^ u[03];
      y[12] = y[13]  ^ y[14];
      y[02] = y[01]  ^ u[00];
      y[05] = y[01]  ^ u[06];
      y[03] = y[05]  ^ y[08];
      t[01] = u[04]  ^ y[12];
      y[15] = t[01]  ^ u[05];
      y[20] = t[01]  ^ u[01];
      y[06] = y[15]  ^ u[07];
      y[10] = y[15]  ^ t[00];
      y[11] = y[20]  ^ y[09];
      y[07] = u[07]  ^ y[11];
      y[17] = y[10]  ^ y[11];
      y[19] = y[10]  ^ y[08];
      y[16] = t[00]  ^ y[11];
      y[21] = y[13]  ^ y[16];
      y[18] = u[00]  ^ y[16];
      t[02] = y[12]  & y[15];
      t[03] = y[03]  & y[06];
      t[04] = t[03]  ^ t[02];
      t[05] = y[04]  & u[07];
      t[06] = t[05]  ^ t[02];
      t[07] = y[13]  & y[16];
      t[08] = y[05]  & y[01];
      t[09] = t[08]  ^ t[07];
      t[10] = y[02]  & y[07];
      t[11] = t[10]  ^ t[07];
      t[12] = y[09]  & y[11];
      t[13] = y[14]  & y[17];
      t[14] = t[13]  ^ t[12];
      t[15] = y[08]  & y[10];
      t[16] = t[15]  ^ t[12];
      t[17] = t[04]  ^ t[14];
      t[18] = t[06]  ^ t[16];
      t[19] = t[09]  ^ t[14];
      t[20] = t[11]  ^ t[16];
      t[21] = t[17]  ^ y[20];
      t[22] = t[18]  ^ y[19];
      t[23] = t[19]  ^ y[21];
      t[24] = t[20]  ^ y[18];
      t[25] = t[21]  ^ t[22];
      t[26] = t[21]  & t[23];
      t[27] = t[24]  ^ t[26];
      t[28] = t[25]  & t[27];
      t[29] = t[28]  ^ t[22];
      t[30] = t[23]  ^ t[24];
      t[31] = t[22]  ^ t[26];
      t[32] = t[31]  & t[30];
      t[33] = t[32]  ^ t[24];
      t[34] = t[23]  ^ t[33];
      t[35] = t[27]  ^ t[33];
      t[36] = t[24]  & t[35];
      t[37] = t[36]  ^ t[34];
      t[38] = t[27]  ^ t[36];
      t[39] = t[29]  & t[38];
      t[40] = t[25]  ^ t[39];
      t[41] = t[40]  ^ t[37];
      t[42] = t[29]  ^ t[33];
      t[43] = t[29]  ^ t[40];
      t[44] = t[33]  ^ t[37];
      t[45] = t[42]  ^ t[41];
      z[00] = t[44]  & y[15];
      z[01] = t[37]  & y[06];
      z[02] = t[33]  & u[07];
      z[03] = t[43]  & y[16];
      z[04] = t[40]  & y[01];
      z[05] = t[29]  & y[07];
      z[06] = t[42]  & y[11];
      z[07] = t[45]  & y[17];
      z[08] = t[41]  & y[10];
      z[09] = t[44]  & y[12];
      z[10] = t[37]  & y[03];
      z[11] = t[33]  & y[04];
      z[12] = t[43]  & y[13];
      z[13] = t[40]  & y[05];
      z[14] = t[29]  & y[02];
      z[15] = t[42]  & y[09];
      z[16] = t[45]  & y[14];
      z[17] = t[41]  & y[08];
      t[46] = z[15]  ^ z[16];
      t[47] = z[10]  ^ z[11];
      t[48] = z[05]  ^ z[13];
      t[49] = z[09]  ^ z[10];
      t[50] = z[02]  ^ z[12];
      t[51] = z[02]  ^ z[05];
      t[52] = z[07]  ^ z[08];
      t[53] = z[00]  ^ z[03];
      t[54] = z[06]  ^ z[07];
      t[55] = z[16]  ^ z[17];
      t[56] = z[12]  ^ t[48];
      t[57] = t[50]  ^ t[53];
      t[58] = z[04]  ^ t[46];
      t[59] = z[03]  ^ t[54];
      t[60] = t[46]  ^ t[57];
      t[61] = z[14]  ^ t[57];
      t[62] = t[52]  ^ t[58];
      t[63] = t[49]  ^ t[58];
      t[64] = z[04]  ^ t[59];
      t[65] = t[61]  ^ t[62];
      t[66] = z[01]  ^ t[63];
      s[00] = t[59]  ^ t[63];
      s[06] = ~t[56] ^ t[62];
      s[07] = ~t[48] ^ t[60];
      t[67] = t[64]  ^ t[65];
      s[03] = t[53]  ^ t[66];
      s[04] = t[51]  ^ t[66];
      s[05] = t[47]  ^ t[65];
      s[01] = ~t[64] ^ s[03];
      s[02] = ~t[55] ^ t[67];
    end
  endfunction // s
endmodule // aes_sbox

//======================================================================
// EOF aes_sbox.v
//======================================================================
