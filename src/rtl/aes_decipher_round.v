//======================================================================
//
// aes_decipher_round.v
// --------------------
// The AES decipher round. A pure combinational module that implements
// the initial round, main round and final round logic for
// decciper operations.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013, 2014, Secworks Sweden AB
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

module aes_decipher_round(
                          input wire            clk,
                          input wire            reset_n,

                          input wire            next,

                          input wire [1 : 0]    keylen,
                          input wire [3 : 0]    round_key_addr,
                          input wire [127 : 0]  round_key,

                          input wire [127 : 0]  block,
                          output wire [127 : 0] new_block,
                          output wire [127 : 0] ready
                         );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter INIT_ROUND  = 0;
  parameter MAIN_ROUND  = 1;
  parameter FINAL_ROUND = 2;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [1 : 0]   sword_ctr_reg;
  reg [1 : 0]   sword_ctr_new;
  reg           sword_ctr_we;
  reg           sword_ctr_inc;
  reg           sword_ctr_rst;

  reg [3 : 0]   round_ctr_reg;
  reg [3 : 0]   round_ctr_new;
  reg           round_ctr_we;
  reg           round_ctr_rst;
  reg           round_ctr_inc;

  reg [31 : 0]  block_w0_reg;
  reg [31 : 0]  block_w0_new;
  reg           block_w0_we;

  reg [31 : 0]  block_w1_reg;
  reg [31 : 0]  block_w1_new;
  reg           block_w1_we;

  reg [31 : 0]  block_w2_reg;
  reg [31 : 0]  block_w2_new;
  reg           block_w2_we;

  reg [31 : 0]  block_w3_reg;
  reg [31 : 0]  block_w3_new;
  reg           block_w3_we;

 
  //----------------------------------------------------------------
  // Gaolis multiplication functions for Inverse MixColumn.
  //----------------------------------------------------------------
  function [7 : 0] gm2(input [7 : 0] op);
    begin
      gm2 = {op[6 : 0], 1'b0} ^ (8'h1b & {8{op[7]}});
    end
  endfunction // gm2

  function [7 : 0] gm4(input [7 : 0] op);
    begin
      gm4 = gm2(gm2(op));
    end
  endfunction // gm4

  function [7 : 0] gm8(input [7 : 0] op);
    begin
      gm8 = gm4(gm4(op));
    end
  endfunction // gm8

  function [7 : 0] gm09(input [7 : 0] op);
    begin
      gm09 = gm8(op) ^ op;
    end
  endfunction // gm09

  function [7 : 0] gm11(input [7 : 0] op);
    begin
      gm11 = gm8(op) ^ gm2(op) ^ op;
    end
  endfunction // gm11

  function [7 : 0] gm13(input [7 : 0] op);
    begin
      gm13 = gm8(op) ^ gm4(op) ^ op;
    end
  endfunction // gm13

  function [7 : 0] gm14(input [7 : 0] op);
    begin
      gm14 = gm8(op) ^ gm4(op) ^ gm2(op);
    end
  endfunction // gm14

  
  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire [7 : 0] sbox00_data;
  wire [7 : 0] sbox01_data;
  wire [7 : 0] sbox02_data;
  wire [7 : 0] sbox03_data;

  reg [7 : 0] tmp_s00_new;
  reg [7 : 0] tmp_s01_new;
  reg [7 : 0] tmp_s02_new;
  reg [7 : 0] tmp_s03_new;
  reg [7 : 0] tmp_s10_new;
  reg [7 : 0] tmp_s11_new;
  reg [7 : 0] tmp_s12_new;
  reg [7 : 0] tmp_s13_new;
  reg [7 : 0] tmp_s20_new;
  reg [7 : 0] tmp_s21_new;
  reg [7 : 0] tmp_s22_new;
  reg [7 : 0] tmp_s23_new;
  reg [7 : 0] tmp_s30_new;
  reg [7 : 0] tmp_s31_new;
  reg [7 : 0] tmp_s32_new;
  reg [7 : 0] tmp_s33_new;

  
  //----------------------------------------------------------------
  // Instantiations.
  //----------------------------------------------------------------
  aes_inv_sbox inv_sbox00(.addr(s00), .data(sbox00_data));
  aes_inv_sbox inv_sbox01(.addr(s01), .data(sbox01_data));
  aes_inv_sbox inv_sbox02(.addr(s02), .data(sbox02_data));
  aes_inv_sbox inv_sbox03(.addr(s03), .data(sbox03_data));


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign s00_new = tmp_s00_new;
  assign s01_new = tmp_s01_new;
  assign s02_new = tmp_s02_new;
  assign s03_new = tmp_s03_new;
  assign s10_new = tmp_s10_new;
  assign s11_new = tmp_s11_new;
  assign s12_new = tmp_s12_new;
  assign s13_new = tmp_s13_new;
  assign s20_new = tmp_s20_new;
  assign s21_new = tmp_s21_new;
  assign s22_new = tmp_s22_new;
  assign s23_new = tmp_s23_new;
  assign s30_new = tmp_s30_new;
  assign s31_new = tmp_s31_new;
  assign s32_new = tmp_s32_new;
  assign s33_new = tmp_s33_new;


  //----------------------------------------------------------------
  // round_logic
  //
  // The logic needed to implement init, main and final rounds.
  //----------------------------------------------------------------
  always @*
    begin : round_logic
      // Wires for internal intermediate values.
      reg [7 : 0] init_s00, s00_0, s00_1, s00_2;
      reg [7 : 0] init_s01, s01_0, s01_1, s01_2;
      reg [7 : 0] init_s02, s02_0, s02_1, s02_2;
      reg [7 : 0] init_s03, s03_0, s03_1, s03_2;
      reg [7 : 0] init_s10, s10_0, s10_1, s10_2;
      reg [7 : 0] init_s11, s11_0, s11_1, s11_2;
      reg [7 : 0] init_s12, s12_0, s12_1, s12_2;
      reg [7 : 0] init_s13, s13_0, s13_1, s13_2;
      reg [7 : 0] init_s20, s20_0, s20_1, s20_2;
      reg [7 : 0] init_s21, s21_0, s21_1, s21_2;
      reg [7 : 0] init_s22, s22_0, s22_1, s22_2;
      reg [7 : 0] init_s23, s23_0, s23_1, s23_2;
      reg [7 : 0] init_s30, s30_0, s30_1, s30_2;
      reg [7 : 0] init_s31, s31_0, s31_1, s31_2;
      reg [7 : 0] init_s32, s32_0, s32_1, s32_2;
      reg [7 : 0] init_s33, s33_0, s33_1, s33_2;

      // InitRound
      init_s00 = s00 ^ round_key[127 : 120];
      init_s10 = s01 ^ round_key[119 : 112];
      init_s20 = s02 ^ round_key[111 : 104];
      init_s30 = s03 ^ round_key[103 :  96];
      init_s01 = s10 ^ round_key[95  :  88];
      init_s11 = s11 ^ round_key[87  :  80];
      init_s21 = s12 ^ round_key[79  :  72];
      init_s31 = s13 ^ round_key[71  :  64];
      init_s02 = s20 ^ round_key[63  :  56];
      init_s12 = s21 ^ round_key[55  :  48];
      init_s22 = s22 ^ round_key[47  :  40];
      init_s32 = s23 ^ round_key[39  :  32];
      init_s03 = s30 ^ round_key[31  :  24];
      init_s13 = s31 ^ round_key[23  :  16];
      init_s23 = s32 ^ round_key[15  :   8];
      init_s33 = s33 ^ round_key[7   :   0];

      // SubBytes and ShiftRows
      // SubBytes is done through connectivity of sbox instances.
      s00_0 = sbox00_data;
      s01_0 = sbox01_data;
      s02_0 = sbox02_data;
      s03_0 = sbox03_data;
      s10_0 = sbox01_data;
      s11_0 = sbox02_data;
      s12_0 = sbox03_data;
      s13_0 = sbox00_data;
      s20_0 = sbox02_data;
      s21_0 = sbox03_data;
      s22_0 = sbox00_data;
      s23_0 = sbox01_data;
      s30_0 = sbox03_data;
      s31_0 = sbox00_data;
      s32_0 = sbox01_data;
      s33_0 = sbox02_data;

      // MixColumns
      s00_1 = gm14(s00_0) ^ gm11(s10_0) ^ gm13(s20_0) ^ gm09(s30_0);
      s10_1 = gm09(s00_0) ^ gm14(s10_0) ^ gm11(s20_0) ^ gm13(s30_0);
      s20_1 = gm13(s00_0) ^ gm09(s10_0) ^ gm14(s20_0) ^ gm11(s30_0);
      s30_1 = gm11(s00_0) ^ gm13(s10_0) ^ gm09(s20_0) ^ gm14(s30_0);
      s01_1 = gm14(s01_0) ^ gm11(s11_0) ^ gm13(s21_0) ^ gm09(s31_0);
      s11_1 = gm09(s01_0) ^ gm14(s11_0) ^ gm11(s21_0) ^ gm13(s31_0);
      s21_1 = gm13(s01_0) ^ gm09(s11_0) ^ gm14(s21_0) ^ gm11(s31_0);
      s31_1 = gm11(s01_0) ^ gm13(s11_0) ^ gm09(s21_0) ^ gm14(s31_0);
      s02_1 = gm14(s02_0) ^ gm11(s12_0) ^ gm13(s22_0) ^ gm09(s32_0);
      s12_1 = gm09(s02_0) ^ gm14(s12_0) ^ gm11(s22_0) ^ gm13(s32_0);
      s22_1 = gm13(s02_0) ^ gm09(s12_0) ^ gm14(s22_0) ^ gm11(s32_0);
      s32_1 = gm11(s02_0) ^ gm13(s12_0) ^ gm09(s22_0) ^ gm14(s32_0);
      s03_1 = gm14(s03_0) ^ gm11(s13_0) ^ gm13(s23_0) ^ gm09(s33_0);
      s13_1 = gm09(s03_0) ^ gm14(s13_0) ^ gm11(s23_0) ^ gm13(s33_0);
      s23_1 = gm13(s03_0) ^ gm09(s13_0) ^ gm14(s23_0) ^ gm11(s33_0);
      s33_1 = gm11(s03_0) ^ gm13(s13_0) ^ gm09(s23_0) ^ gm14(s33_0);

      // AddRoundKey
      s00_2 = s00_1 ^ round_key[127 : 120];
      s01_2 = s01_1 ^ round_key[119 : 112];
      s02_2 = s02_1 ^ round_key[111 : 104];
      s03_2 = s03_1 ^ round_key[103 :  96];
      s10_2 = s10_1 ^ round_key[95  :  88];
      s11_2 = s11_1 ^ round_key[87  :  80];
      s12_2 = s12_1 ^ round_key[79  :  72];
      s13_2 = s13_1 ^ round_key[71  :  64];
      s20_2 = s20_1 ^ round_key[63  :  56];
      s21_2 = s21_1 ^ round_key[55  :  48];
      s22_2 = s22_1 ^ round_key[47  :  40];
      s23_2 = s23_1 ^ round_key[39  :  32];
      s30_2 = s30_1 ^ round_key[31  :  24];
      s31_2 = s31_1 ^ round_key[23  :  16];
      s32_2 = s32_1 ^ round_key[15  :   8];
      s33_2 = s33_1 ^ round_key[7   :   0];

      case (round_type)
        INIT_ROUND:
          begin
            tmp_s00_new = init_s00;
            tmp_s01_new = init_s10;
            tmp_s02_new = init_s20;
            tmp_s03_new = init_s30;
            tmp_s10_new = init_s01;
            tmp_s11_new = init_s11;
            tmp_s12_new = init_s21;
            tmp_s13_new = init_s31;
            tmp_s20_new = init_s02;
            tmp_s21_new = init_s12;
            tmp_s22_new = init_s22;
            tmp_s23_new = init_s32;
            tmp_s30_new = init_s03;
            tmp_s31_new = init_s13;
            tmp_s32_new = init_s23;
            tmp_s33_new = init_s33;
          end

        MAIN_ROUND:
          begin
            tmp_s00_new = s00_2;
            tmp_s01_new = s01_2;
            tmp_s02_new = s02_2;
            tmp_s03_new = s03_2;
            tmp_s10_new = s10_2;
            tmp_s11_new = s11_2;
            tmp_s12_new = s12_2;
            tmp_s13_new = s13_2;
            tmp_s20_new = s20_2;
            tmp_s21_new = s21_2;
            tmp_s22_new = s22_2;
            tmp_s23_new = s23_2;
            tmp_s30_new = s30_2;
            tmp_s31_new = s31_2;
            tmp_s32_new = s32_2;
            tmp_s33_new = s33_2;
          end

        FINAL_ROUND:
          begin
            tmp_s00_new = s00_1;
            tmp_s01_new = s01_1;
            tmp_s02_new = s02_1;
            tmp_s03_new = s03_1;
            tmp_s10_new = s10_1;
            tmp_s11_new = s11_1;
            tmp_s12_new = s12_1;
            tmp_s13_new = s13_1;
            tmp_s20_new = s20_1;
            tmp_s21_new = s21_1;
            tmp_s22_new = s22_1;
            tmp_s23_new = s23_1;
            tmp_s30_new = s30_1;
            tmp_s31_new = s31_1;
            tmp_s32_new = s32_1;
            tmp_s33_new = s33_1;
          end

        default:
          begin
            tmp_s00_new = 8'h00;
            tmp_s01_new = 8'h00;
            tmp_s02_new = 8'h00;
            tmp_s03_new = 8'h00;
            tmp_s10_new = 8'h00;
            tmp_s11_new = 8'h00;
            tmp_s12_new = 8'h00;
            tmp_s13_new = 8'h00;
            tmp_s20_new = 8'h00;
            tmp_s21_new = 8'h00;
            tmp_s22_new = 8'h00;
            tmp_s23_new = 8'h00;
            tmp_s30_new = 8'h00;
            tmp_s31_new = 8'h00;
            tmp_s32_new = 8'h00;
            tmp_s33_new = 8'h00;
          end
      endcase // case (round_type)
    end // round_logic


  //----------------------------------------------------------------
  // sword_ctr
  //
  // The subbytes word counter with reset and increase logic.
  //----------------------------------------------------------------
  always @*
    begin : sword_ctr
      sword_ctr_new = 2'h0;
      sword_ctr_we  = 1'b0;

      if (sword_ctr_rst)
        begin
          sword_ctr_we  = 1'b1;
        end
      else if (sword_ctr_inc)
        begin
          sword_ctr_new = sword_ctr_reg + 1'b1;
          sword_ctr_we  = 1'b0;
        end
    end // sword_ctr


  //----------------------------------------------------------------
  // round_ctr
  //
  // The round counter with reset and increase logic.
  //----------------------------------------------------------------
  always @*
    begin : round_ctr
      round_ctr_new = 4'h0;
      round_ctr_we  = 1'b0;

      if (round_ctr_rst)
        begin
          round_ctr_we  = 1'b1;
        end
      else if (round_ctr_inc)
        begin
          round_ctr_new = round_ctr_reg + 1'b1;
          round_ctr_we  = 1'b0;
        end
    end // round_ctr

endmodule // aes_decipher_round

//======================================================================
// EOF aes_decipher_round.v
//======================================================================
