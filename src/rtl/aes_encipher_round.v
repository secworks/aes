//======================================================================
//
// aes_encipher_round.v
// --------------------
// The AES encipher round. A pure combinational module that implements
// the initial round, main round and final round logic for
// enciper operations.
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
 
module aes_encipher_round(
                          input wire            clk,
                          input wire            reset_n,

                          input wire            next,

                          input wire            keylen,
                          input wire [3 : 0]    round,
                          input wire [127 : 0]  round_key,

                          output wire [31 : 0]  sboxw,
                          input wire  [31 : 0]  new_sboxw,

                          input wire [127 : 0]  block,
                          output wire [127 : 0] new_block,
                          output wire           ready
                         );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter AES_128_BIT_KEY = 1'h0;
  parameter AES_256_BIT_KEY = 1'h1;

  parameter AES128_ROUNDS = 4'ha;
  parameter AES256_ROUNDS = 4'he;

  parameter NO_UPDATE    = 0;
  parameter INIT_UPDATE  = 1;
  parameter SBOX_UPDATE  = 2;
  parameter MAIN_UPDATE  = 3;
  parameter FINAL_UPDATE = 4;

  parameter CTRL_IDLE = 2'h0;
  parameter CTRL_INIT = 2'h1;
  parameter CTRL_DONE = 2'h2;
  
 
  //----------------------------------------------------------------
  // Gaolis multiplication functions for MixColumn.
  //----------------------------------------------------------------
  function [7 : 0] gm2(input [7 : 0] op);
    begin
      gm2 = {op[6 : 0], 1'b0} ^ (8'h1b & {8{op[7]}});
    end
  endfunction // gm2

  function [7 : 0] gm3(input [7 : 0] op);
    begin
      gm3 = gm2(op) ^ op;
    end
  endfunction // gm3


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg [1 : 0]  sword_ctr_reg;
  reg [1 : 0]  sword_ctr_new;
  reg          sword_ctr_we;
  reg          sword_ctr_inc;
  reg          sword_ctr_rst;

  reg [3 : 0]  round_ctr_reg;
  reg [3 : 0]  round_ctr_new;
  reg          round_ctr_we;
  reg          round_ctr_rst;
  reg          round_ctr_inc;

  reg [31 : 0] block_w0_reg;
  reg [31 : 0] block_w0_new;
  reg          block_w0_we;

  reg [31 : 0] block_w1_reg;
  reg [31 : 0] block_w1_new;
  reg          block_w1_we;

  reg [31 : 0] block_w2_reg;
  reg [31 : 0] block_w2_new;
  reg          block_w2_we;

  reg [31 : 0] block_w3_reg;
  reg [31 : 0] block_w3_new;
  reg          block_w3_we;

  reg [1 : 0]  enc_ctrl_reg;
  reg [1 : 0]  enc_ctrl_new;
  reg          enc_ctrl_we;

  reg          ready_reg;
  reg          ready_new;
  reg          ready_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [2 : 0] update_type;

  reg [31 : 0 ] tmp_sboxw;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign sboxw = tmp_sboxw;
  assign ready = ready_reg;


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin: reg_update
      if (!reset_n)
        begin
          block_w0_reg  <= 32'h00000000;
          block_w1_reg  <= 32'h00000000;
          block_w2_reg  <= 32'h00000000;
          block_w3_reg  <= 32'h00000000;
          sword_ctr_reg <= 2'h0;
          round_ctr_reg <= 4'h0;
          ready_reg     <= 1;
          enc_ctrl_reg  <= CTRL_IDLE;
        end
      else
        begin
          if (block_w0_we)
            begin
              block_w0_reg <= block_w0_new;
            end

          if (block_w1_we)
            begin
              block_w1_reg <= block_w1_new;
            end

          if (block_w2_we)
            begin
              block_w2_reg <= block_w2_new;
            end

          if (block_w3_we)
            begin
              block_w3_reg <= block_w3_new;
            end

          if (sword_ctr_we)
            begin
              sword_ctr_reg <= sword_ctr_new;
            end

          if (round_ctr_we)
            begin
              round_ctr_reg <= round_ctr_new;
            end

          if (ready_we)
            begin
              ready_reg <= ready_new;
            end

          if (enc_ctrl_we)
            begin
              enc_ctrl_reg <= enc_ctrl_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // round_logic
  //
  // The logic needed to implement init, main and final rounds.
  //----------------------------------------------------------------
  always @*
    begin : round_logic
      // Wires for internal intermediate values.
      reg [7 : 0] s00_0, s00_1, s00_2;
      reg [7 : 0] s01_0, s01_1, s01_2;
      reg [7 : 0] s02_0, s02_1, s02_2;
      reg [7 : 0] s03_0, s03_1, s03_2;
      reg [7 : 0] s10_0, s10_1, s10_2;
      reg [7 : 0] s11_0, s11_1, s11_2;
      reg [7 : 0] s12_0, s12_1, s12_2;
      reg [7 : 0] s13_0, s13_1, s13_2;
      reg [7 : 0] s20_0, s20_1, s20_2;
      reg [7 : 0] s21_0, s21_1, s21_2;
      reg [7 : 0] s22_0, s22_1, s22_2;
      reg [7 : 0] s23_0, s23_1, s23_2;
      reg [7 : 0] s30_0, s30_1, s30_2;
      reg [7 : 0] s31_0, s31_1, s31_2;
      reg [7 : 0] s32_0, s32_1, s32_2;
      reg [7 : 0] s33_0, s33_1, s33_2;

      // Logic common to normal round updates
      // as well as final round update.
      // Shiftrows
      s00_0 = block_w0_reg[031 : 024];
      s01_0 = block_w0_reg[023 : 016];
      s02_0 = block_w0_reg[015 : 008];
      s03_0 = block_w0_reg[007 : 000];

      s10_0 = block_w1_reg[023 : 016];
      s11_0 = block_w1_reg[015 : 008];
      s12_0 = block_w1_reg[007 : 000];
      s13_0 = block_w1_reg[031 : 024];

      s20_0 = block_w2_reg[015 : 008];
      s21_0 = block_w2_reg[007 : 000];
      s22_0 = block_w2_reg[031 : 024];
      s23_0 = block_w2_reg[023 : 016];

      s30_0 = block_w3_reg[007 : 000];
      s31_0 = block_w3_reg[031 : 024];
      s32_0 = block_w3_reg[023 : 016];
      s33_0 = block_w3_reg[015 : 008];

      // MixColumns
      s00_1 = gm2(s00_0) ^ gm3(s10_0) ^ s20_0      ^ s30_0;
      s10_1 = s00_0      ^ gm2(s10_0) ^ gm3(s20_0) ^ s30_0;
      s20_1 = s00_0      ^ s10_0      ^ gm2(s20_0) ^ gm3(s30_0);
      s30_1 = gm3(s00_0) ^ s10_0      ^ s20_0      ^ gm2(s30_0);

      s01_1 = gm2(s01_0) ^ gm3(s11_0) ^ s21_0      ^ s31_0;
      s11_1 = s01_0      ^ gm2(s11_0) ^ gm3(s21_0) ^ s31_0;
      s21_1 = s01_0      ^ s11_0      ^ gm2(s21_0) ^ gm3(s31_0);
      s31_1 = gm3(s01_0) ^ s11_0      ^ s21_1      ^ gm2(s31_0);

      s02_1 = gm2(s02_0) ^ gm3(s12_0) ^ s22_0      ^ s32_0;
      s12_1 = s02_0      ^ gm2(s12_0) ^ gm3(s22_0) ^ s32_0;
      s22_1 = s02_0      ^ s12_0      ^ gm2(s22_0) ^ gm3(s32_0);
      s32_1 = gm3(s02_0) ^ s12_0      ^ s22_1      ^ gm2(s32_0);

      s03_1 = gm2(s03_0) ^ gm3(s13_0) ^ s23_0      ^ s33_0;
      s13_1 = s03_0      ^ gm2(s13_0) ^ gm3(s23_0) ^ s33_0;
      s23_1 = s03_0      ^ s13_0      ^ gm2(s23_0) ^ gm3(s33_0);
      s33_1 = gm3(s03_0) ^ s13_0      ^ s23_1      ^ gm2(s33_0);

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

      // Update based on update type.
      case (update_type)
        NO_UPDATE:
          begin
            tmp_sboxw    = 32'h00000000;
            block_w0_new = 32'h00000000;
            block_w0_we  = 0;
            block_w1_new = 32'h00000000;
            block_w1_we  = 0;
            block_w2_new = 32'h00000000;
            block_w2_we  = 0;
            block_w3_new = 32'h00000000;
            block_w3_we  = 0;
          end

        // InitRound
        INIT_UPDATE:
          begin
            block_w0_new = block[127 : 096] ^ round_key[127 : 096];
            block_w1_new = block[095 : 064] ^ round_key[095 : 064];
            block_w2_new = block[063 : 032] ^ round_key[063 : 032];
            block_w3_new = block[031 : 000] ^ round_key[031 : 000];
            block_w0_we  = 1;
            block_w1_we  = 1;
            block_w2_we  = 1;
            block_w3_we  = 1;
          end

        // SubBytes update using the module external Sboxes.
        SBOX_UPDATE:
          begin
            case (sword_ctr_reg)
              2'h0:
                begin
                  tmp_sboxw    = block_w0_reg;
                  block_w0_new = new_sboxw;
                  block_w0_we  = 1;
                end

              2'h1:
                begin
                  tmp_sboxw    = block_w1_reg;
                  block_w1_new = new_sboxw;
                  block_w1_we  = 1;
                end

              2'h2:
                begin
                  tmp_sboxw    = block_w2_reg;
                  block_w2_new = new_sboxw;
                  block_w2_we  = 1;
                end

              2'h3:
                begin
                  tmp_sboxw    = block_w3_reg;
                  block_w3_new = new_sboxw;
                  block_w3_we  = 1;
                end
            endcase // case (sbox_mux_ctrl_reg)
          end

        MAIN_UPDATE:
          begin
            block_w0_new = {s00_2, s01_2, s02_2, s03_2};
            block_w1_new = {s10_2, s11_2, s12_2, s13_2};
            block_w2_new = {s20_2, s21_2, s22_2, s23_2};
            block_w3_new = {s30_2, s31_2, s32_2, s33_2};
            block_w0_we  = 1;
            block_w1_we  = 1;
            block_w2_we  = 1;
            block_w3_we  = 1;
          end

        FINAL_UPDATE:
          begin
            block_w0_new = {s00_1, s01_1, s02_1, s03_1};
            block_w1_new = {s10_1, s11_1, s12_1, s13_1};
            block_w2_new = {s20_1, s21_1, s22_1, s23_1};
            block_w3_new = {s30_1, s31_1, s32_1, s33_1};
            block_w0_we  = 1;
            block_w1_we  = 1;
            block_w2_we  = 1;
            block_w3_we  = 1;
          end
      endcase // case (update_type)
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


  //----------------------------------------------------------------
  // encipher_ctrl
  //
  //
  // The FSM that controls the encipher operations.
  //----------------------------------------------------------------
  always @*
    begin: encipher_ctrl
      // Default assignments.
      sword_ctr_inc = 0;
      sword_ctr_rst = 0;
      round_ctr_rst = 0;
      round_ctr_inc = 0;
      ready_new     = 0;
      ready_we      = 0;
      update_type   = NO_UPDATE;
      enc_ctrl_new  = CTRL_IDLE;
      enc_ctrl_we   = 0;
    
      case(enc_ctrl_reg)
        CTRL_IDLE:
          begin
          end

        default:
          begin
          end
      endcase // case (enc_ctrl_reg)

    end // encipher_ctrl

endmodule // aes_encipher_round

//======================================================================
// EOF aes_encipher_round.v
//======================================================================
