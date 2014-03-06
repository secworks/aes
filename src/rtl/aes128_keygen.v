//======================================================================
//
// aes_keygen.v
// ------------
// The AES round key generator.xs
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

module aes_keygen(
                  input wire [127 : 0]  key,
                  input wire            encdec,
                  input wire            init,
                  input wire [3 : 0]    addr,

                  output wire [127 : 0] round_key,
                  output wire           ready
                 );

  
  //----------------------------------------------------------------
  // Parameters.
  //----------------------------------------------------------------
  parameter NUM_ROUNDS = 10;
  
  parameter CTRL_IDLE = 0;
  parameter CTRL_INIT = 1;
  parameter CTRL_NEXT = 2;
  parameter CTRL_DONE = 3;

  
  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [127 : 0] key_mem [0 : 9];
  reg           key_mem_we;

  reg [3 : 0] round_ctr_reg;
  reg [3 : 0] round_ctr_new;
  reg         round_ctr_rst;
  reg         round_ctr_dec;
  reg         round_ctr_inc;
  reg         round_ctr_we;
  
  reg [2 : 0] keygen_ctrl_reg;
  reg [2 : 0] keygen_ctrl_reg;
  reg         keygen_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [127 : 0] tmp_round_key;
  reg           tmp_ready;
  

  //----------------------------------------------------------------
  // Concurrent assignments for ports.
  //----------------------------------------------------------------
  round_key = tmp_round_key;
  ready     = tmp_ready;
  
    
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
          round_ctr_reg   <= 4'h0;
          keygen_ctrl_reg <= CTRL_IDLE;
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

          if (keygen_ctrl_we)
            begin
              keygen_ctrl_reg <= keygen_ctrl_new;
            end
        end
    end // reg_update

                  
  //----------------------------------------------------------------
  // round_key_mux
  //
  // Read access mux to the round keys.
  //----------------------------------------------------------------
  always @*
    begin: round_key_mux
      case(addr)
        0:       tmp_round_key = key_mem[0];
        1:       tmp_round_key = key_mem[1];
        2:       tmp_round_key = key_mem[2];
        3:       tmp_round_key = key_mem[3];
        4:       tmp_round_key = key_mem[4];
        5:       tmp_round_key = key_mem[5];
        6:       tmp_round_key = key_mem[6];
        7:       tmp_round_key = key_mem[7];
        8:       tmp_round_key = key_mem[8];
        9:       tmp_round_key = key_mem[9];
        default: tmp_round_key = 128'h00000000000000000000000000000000;
      endcase // case (addr)
    end // round_key_mux

  
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
  // keygen_ctrl
  //
  //
  // The FSM that controls the round key generation.
  //----------------------------------------------------------------
  always @*
    begin: keygen_ctrl
      // Default assignments.
      tmp_ready   = 0;
      keygen_ctrl_new = CTRL_IDLE;
      keygen_ctrl_we  = 0;

      case(keygen_ctrl_reg)
        CTRL_IDLE:
          begin
            tmp_ready = 1;

            if (init)
              begin
                keygen_ctrl_new = CTRL_INIT;
                keygen_ctrl_we  = 1;
              end
          end

        CTRL_INIT:
          begin
            // NOTE: TEMPORARY JUMPBACK!
            keygen_ctrl_new = CTRL_IDLE;
            keygen_ctrl_we  = 1;
          end
      
        default:
          begin
          end
      endcase // case (keygen_ctrl_reg)

    end // keygen_ctrl
endmodule // aes_keygen

//======================================================================
// EOF aes_keygen.v
//======================================================================
