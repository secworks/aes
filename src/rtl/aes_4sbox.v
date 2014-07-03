//======================================================================
//
// aes_4sbox.v
// ----------
// The AES S-box word memory. Basically four instances of the
// AES S-box
//
//
// Copyright (c) 2013 Secworks Sweden AB
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

module aes_4sbox(
                 input wire  [31 : 0] word,
                 output wire [31 : 0] substword
                );


  //----------------------------------------------------------------
  // sbox instantiations.
  //----------------------------------------------------------------
  aes_sbox sbox0(.addr(word[31 : 24]), .data(substword[31 : 24));
  aes_sbox sbox1(.addr(word[23 : 16]), .data(substword[23 : 16));
  aes_sbox sbox2(.addr(word[15 : 08]), .data(substword[15 : 08));
  aes_sbox sbox3(.addr(word[07 : 00]), .data(substword[07 : 00));

endmodule // aes_4sbox

//======================================================================
// EOF aes_4sbox.v
//======================================================================
