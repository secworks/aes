//======================================================================
//
// aes.v
// --------
// Top level wrapper for the AES block cipher core.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013, 2014 Secworks Sweden AB
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

module aes(
           // Clock and reset.
           input wire           clk,
           input wire           reset_n,

           // Control.
           input wire           cs,
           input wire           we,

           // Data ports.
           input wire  [7 : 0]  address,
           input wire  [31 : 0] write_data,
           output wire [31 : 0] read_data,
           output wire          error
          );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0       = 8'h00;
  localparam ADDR_NAME1       = 8'h01;
  localparam ADDR_VERSION     = 8'h02;

  localparam ADDR_CTRL        = 8'h08;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;

  localparam ADDR_CONFIG      = 8'h09;
  localparam CTRL_ENCDEC_BIT  = 0;
  localparam CTRL_KEYLEN_BIT  = 1;

  localparam ADDR_STATUS      = 8'h0a;
  localparam STATUS_READY_BIT = 0;
  localparam STATUS_VALID_BIT = 1;

  localparam ADDR_KEY0        = 8'h10;
  localparam ADDR_KEY1        = 8'h11;
  localparam ADDR_KEY2        = 8'h12;
  localparam ADDR_KEY3        = 8'h13;
  localparam ADDR_KEY4        = 8'h14;
  localparam ADDR_KEY5        = 8'h15;
  localparam ADDR_KEY6        = 8'h16;
  localparam ADDR_KEY7        = 8'h17;

  localparam ADDR_BLOCK0      = 8'h20;
  localparam ADDR_BLOCK1      = 8'h21;
  localparam ADDR_BLOCK2      = 8'h22;
  localparam ADDR_BLOCK3      = 8'h23;

  localparam ADDR_RESULT0     = 8'h30;
  localparam ADDR_RESULT1     = 8'h31;
  localparam ADDR_RESULT2     = 8'h32;
  localparam ADDR_RESULT3     = 8'h33;

  localparam CORE_NAME0       = 32'h6165732d; // "aes-"
  localparam CORE_NAME1       = 32'h31323820; // "128 "
  localparam CORE_VERSION     = 32'h302e3530; // "0.50"


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg init_new;

  reg next_reg;
  reg next_new;

  reg encdec_reg;
  reg keylen_reg;
  reg config_we;

  reg [31 : 0] block0_reg;
  reg          block0_we;
  reg [31 : 0] block1_reg;
  reg          block1_we;
  reg [31 : 0] block2_reg;
  reg          block2_we;
  reg [31 : 0] block3_reg;
  reg          block3_we;

  reg [31 : 0] key0_reg;
  reg          key0_we;
  reg [31 : 0] key1_reg;
  reg          key1_we;
  reg [31 : 0] key2_reg;
  reg          key2_we;
  reg [31 : 0] key3_reg;
  reg          key3_we;
  reg [31 : 0] key4_reg;
  reg          key4_we;
  reg [31 : 0] key5_reg;
  reg          key5_we;
  reg [31 : 0] key6_reg;
  reg          key6_we;
  reg [31 : 0] key7_reg;
  reg          key7_we;

  reg [127 : 0] result_reg;
  reg           valid_reg;
  reg           ready_reg;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;
  reg            tmp_error;

  wire           core_encdec;
  wire           core_init;
  wire           core_next;
  wire           core_ready;
  wire [255 : 0] core_key;
  wire           core_keylen;
  wire [127 : 0] core_block;
  wire [127 : 0] core_result;
  wire           core_valid;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign read_data = tmp_read_data;
  assign error     = tmp_error;

  assign core_key = {key0_reg, key1_reg, key2_reg, key3_reg,
                     key4_reg, key5_reg, key6_reg, key7_reg};

  assign core_block  = {block0_reg, block1_reg, block2_reg, block3_reg};
  assign core_init   = init_reg;
  assign core_next   = next_reg;
  assign core_encdec = encdec_reg;
  assign core_keylen = keylen_reg;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_core core(
                .clk(clk),
                .reset_n(reset_n),

                .encdec(core_encdec),
                .init(core_init),
                .next(core_next),
                .ready(core_ready),

                .key(core_key),
                .keylen(core_keylen),

                .block(core_block),
                .result(core_result),
                .result_valid(core_valid)
               );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin
      if (!reset_n)
        begin
          block0_reg <= 32'h0;
          block1_reg <= 32'h0;
          block2_reg <= 32'h0;
          block3_reg <= 32'h0;

          key0_reg   <= 32'h0;
          key1_reg   <= 32'h0;
          key2_reg   <= 32'h0;
          key3_reg   <= 32'h0;
          key4_reg   <= 32'h0;
          key5_reg   <= 32'h0;
          key6_reg   <= 32'h0;
          key7_reg   <= 32'h0;

          init_reg   <= 0;
          next_reg   <= 0;
          encdec_reg <= 0;
          keylen_reg <= 0;

          result_reg <= 128'h0;
          valid_reg  <= 0;
          ready_reg  <= 0;
        end
      else
        begin
          ready_reg  <= core_ready;
          valid_reg  <= core_valid;
          result_reg <= core_result;
          init_reg   <= init_new;
          next_reg   <= next_new;

          if (config_we)
            begin
              encdec_reg <= write_data[CTRL_ENCDEC_BIT];
              keylen_reg <= write_data[CTRL_KEYLEN_BIT];
            end

          if (key0_we)
            key0_reg <= write_data;

          if (key1_we)
            key1_reg <= write_data;

          if (key2_we)
            key2_reg <= write_data;

          if (key3_we)
            key3_reg <= write_data;

          if (key4_we)
            key4_reg <= write_data;

          if (key5_we)
            key5_reg <= write_data;

          if (key6_we)
            key6_reg <= write_data;

          if (key7_we)
            key7_reg <= write_data;

          if (block0_we)
            block0_reg <= write_data;

          if (block1_we)
            block1_reg <= write_data;

          if (block2_we)
            block2_reg <= write_data;

          if (block3_we)
            block3_reg <= write_data;
        end
    end // reg_update


  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  always @*
    begin : api
      init_new      = 0;
      next_new      = 0;
      config_we     = 0;
      key0_we       = 0;
      key1_we       = 0;
      key2_we       = 0;
      key3_we       = 0;
      key4_we       = 0;
      key5_we       = 0;
      key6_we       = 0;
      key7_we       = 0;
      block0_we     = 0;
      block1_we     = 0;
      block2_we     = 0;
      block3_we     = 0;
      tmp_read_data = 32'h0;
      tmp_error     = 0;

      if (cs)
        begin
          if (we)
            begin
              case (address)
                // Write operations.
                ADDR_CTRL:
                  begin
                    init_new = write_data[CTRL_INIT_BIT];
                    next_new = write_data[CTRL_NEXT_BIT];
                  end

                ADDR_CONFIG: config_we = 1;
                ADDR_KEY0:   key0_we = 1;
                ADDR_KEY1:   key1_we = 1;
                ADDR_KEY2:   key2_we = 1;
                ADDR_KEY3:   key3_we = 1;
                ADDR_KEY4:   key4_we = 1;
                ADDR_KEY5:   key5_we = 1;
                ADDR_KEY6:   key6_we = 1;
                ADDR_KEY7:   key7_we = 1;
                ADDR_BLOCK0: block0_we = 1;
                ADDR_BLOCK1: block1_we = 1;
                ADDR_BLOCK2: block2_we = 1;
                ADDR_BLOCK3: block3_we = 1;

                default:
                  begin
                    tmp_error = 1;
                  end
              endcase // case (address)
            end // if (we)

          else
            begin
              case (address)
                // Read operations.
                ADDR_NAME0:   tmp_read_data = CORE_NAME0;
                ADDR_NAME1:   tmp_read_data = CORE_NAME1;
                ADDR_VERSION: tmp_read_data = CORE_VERSION;
                ADDR_CTRL:    tmp_read_data = {28'h0, keylen_reg, encdec_reg, next_reg, init_reg};
                ADDR_STATUS:  tmp_read_data = {30'h0, valid_reg, ready_reg};
                ADDR_KEY0:    tmp_read_data = key0_reg;
                ADDR_KEY1:    tmp_read_data = key1_reg;
                ADDR_KEY2:    tmp_read_data = key2_reg;
                ADDR_KEY3:    tmp_read_data = key3_reg;
                ADDR_KEY4:    tmp_read_data = key4_reg;
                ADDR_KEY5:    tmp_read_data = key5_reg;
                ADDR_KEY6:    tmp_read_data = key6_reg;
                ADDR_KEY7:    tmp_read_data = key7_reg;
                ADDR_BLOCK0:  tmp_read_data = block0_reg;
                ADDR_BLOCK1:  tmp_read_data = block1_reg;
                ADDR_BLOCK2:  tmp_read_data = block2_reg;
                ADDR_BLOCK3:  tmp_read_data = block3_reg;
                ADDR_RESULT0: tmp_read_data = result_reg[127 : 96];
                ADDR_RESULT1: tmp_read_data = result_reg[95 : 64];
                ADDR_RESULT2: tmp_read_data = result_reg[63 : 32];
                ADDR_RESULT3: tmp_read_data = result_reg[31 : 0];

                default:
                  begin
                    tmp_error = 1;
                  end
              endcase // case (address)
            end
        end
    end // addr_decoder
endmodule // aes

//======================================================================
// EOF aes.v
//======================================================================
