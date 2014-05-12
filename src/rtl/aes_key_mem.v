//======================================================================
//
// aes_key_mem.v
// -------------
// The AES key memort including round key generator.
//
//
// Author: Joachim Strombergson
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

module aes_key_mem(
                   input wire            clk,
                   input wire            reset_n,

                   input wire [255 : 0]  key,
                   input wire [1   : 0]  keylen,
                   input wire            init,

                   input wire    [3 : 0] round,
                   output wire [127 : 0] round_key,
                   output wire           ready
                  );

  
  //----------------------------------------------------------------
  // Parameters.
  //----------------------------------------------------------------
  parameter AES_128_BIT_KEY = 0;
  parameter AES_192_BIT_KEY = 1;
  parameter AES_256_BIT_KEY = 2;

  parameter AES_128_NUM_ROUNDS = 10;
  parameter AES_128_NUM_ROUNDS = 12;
  parameter AES_128_NUM_ROUNDS = 14;
  
  parameter CTRL_IDLE = 0;
  parameter CTRL_INIT = 1;
  parameter CTRL_NEXT = 2;
  parameter CTRL_DONE = 3;

  
  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [127 : 0] key_mem [0 : 13];
  reg [127 : 0] key_mem_new;
  reg           key_mem_we;

  reg [3 : 0] round_ctr_reg;
  reg [3 : 0] round_ctr_new;
  reg         round_ctr_rst;
  reg         round_ctr_inc;
  reg         round_ctr_we;
  
  reg [2 : 0] key_mem_ctrl_reg;
  reg [2 : 0] key_mem_ctrl_new;
  reg         key_mem_ctrl_we;

  reg [7 : 0] sbox0_addr;
  reg [7 : 0] sbox1_addr;
  reg [7 : 0] sbox2_addr;
  reg [7 : 0] sbox3_addr;

  wire [7 : 0] sbox0_data;
  wire [7 : 0] sbox1_data;
  wire [7 : 0] sbox2_data;
  wire [7 : 0] sbox3_data;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [127 : 0] tmp_round_key;
  reg           tmp_ready;
  

  //----------------------------------------------------------------
  // Instantiations.
  //----------------------------------------------------------------
  aes_sbox sbox0(.addr(sbox0_addr), .data(sbox0_data));
  aes_sbox sbox1(.addr(sbox1_addr), .data(sbox1_data));
  aes_sbox sbox2(.addr(sbox2_addr), .data(sbox2_data));
  aes_sbox sbox3(.addr(sbox3_addr), .data(sbox3_data));

  
  //----------------------------------------------------------------
  // Concurrent assignments for ports.
  //----------------------------------------------------------------
  assign round_key = tmp_round_key;
  assign ready     = tmp_ready;
  
    
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
          key_mem [0]     <= 128'h00000000000000000000000000000000;
          key_mem [1]     <= 128'h00000000000000000000000000000000;
          key_mem [2]     <= 128'h00000000000000000000000000000000;
          key_mem [3]     <= 128'h00000000000000000000000000000000;
          key_mem [4]     <= 128'h00000000000000000000000000000000;
          key_mem [5]     <= 128'h00000000000000000000000000000000;
          key_mem [6]     <= 128'h00000000000000000000000000000000;
          key_mem [7]     <= 128'h00000000000000000000000000000000;
          key_mem [8]     <= 128'h00000000000000000000000000000000;
          key_mem [9]     <= 128'h00000000000000000000000000000000;
          key_mem [10]    <= 128'h00000000000000000000000000000000;
          key_mem [11]    <= 128'h00000000000000000000000000000000;
          key_mem [12]    <= 128'h00000000000000000000000000000000;
          key_mem [13]    <= 128'h00000000000000000000000000000000;
          round_ctr_reg   <= 4'h0;
          key_mem_ctrl_reg <= CTRL_IDLE;
        end
      else
        begin
          if (round_ctr_we)
            begin
              round_ctr_reg <= round_ctr_new;
                  end
          
          if (key_mem_we)
            begin
              key_mem[round_ctr_reg] = key_mem_new;
            end

          if (key_mem_ctrl_we)
            begin
              key_mem_ctrl_reg <= key_mem_ctrl_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // key_mem_read
  //
  // Combinational read port for the key memory.
  //----------------------------------------------------------------
  always @*
    begin : key_mem_read
      tmp_round_key = key_mem[round];
    end // key_mem_read

  
  //----------------------------------------------------------------
  // round_key_gen
  //
  //
  // The round key generator logic
  //----------------------------------------------------------------
  always @*
    begin: round_key_gen
      // Default assignments.
      key_mem_we  = 0;
      key_mem_new = 128'h00000000000000000000000000000000;

    end // round_key_gen

  
  //----------------------------------------------------------------
  // key_mem_ctrl
  //
  //
  // The FSM that controls the round key generation.
  //----------------------------------------------------------------
  always @*
    begin: key_mem_ctrl
      // Default assignments.
      tmp_ready   = 0;
      key_mem_ctrl_new = CTRL_IDLE;
      key_mem_ctrl_we  = 0;

      case(key_mem_ctrl_reg)
        CTRL_IDLE:
          begin
            tmp_ready = 1;

            if (init)
              begin
                key_mem_ctrl_new = CTRL_INIT;
                key_mem_ctrl_we  = 1;
              end
          end

        CTRL_INIT:
          begin
            // NOTE: TEMPORARY JUMPBACK!
            key_mem_ctrl_new = CTRL_IDLE;
            key_mem_ctrl_we  = 1;
          end
      
        default:
          begin
          end
      endcase // case (key_mem_ctrl_reg)

    end // key_mem_ctrl
endmodule // aes_key_mem

//======================================================================
// EOF aes_key_mem.v
//======================================================================
