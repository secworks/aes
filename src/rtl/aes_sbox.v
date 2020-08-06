//======================================================================
//
// aes_sbox.v
// ----------
// The AES S-box. Basically a 256 Byte ROM. This implementation
// contains four parallel S-boxes to handle a 32 bit word.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014, Secworks Sweden AB
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

module aes_sbox(
                input wire [31 : 0]  sboxw,
                output wire [31 : 0] new_sboxw
               );

  //----------------------------------------------------------------
  // Four parallel sboxes.
  //----------------------------------------------------------------
  cmt_sbox sb0(sboxw[31 : 24], new_sboxw[31 : 24]);
  cmt_sbox sb1(sboxw[23 : 16], new_sboxw[23 : 16]);
  cmt_sbox sb2(sboxw[15 : 08], new_sboxw[15 : 08]);
  cmt_sbox sb3(sboxw[07 : 00], new_sboxw[07 : 00]);

endmodule // aes_sbox

//======================================================================
// EOF aes_sbox.v
//======================================================================
