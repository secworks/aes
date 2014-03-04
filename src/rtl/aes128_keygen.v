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
                  input wire            enc_dec,
                  input wire            init,
                  input wire            next,
                  output wire [127 : 0] round_key
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
  
  reg [2 : 0] round_ctrl_reg;
  reg [2 : 0] round_ctrl_reg;
  reg         round_ctrl_we;
  

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------


  //----------------------------------------------------------------
  // Concurrent assignments for ports.
  //----------------------------------------------------------------
  assign data = tmp_data;
  
    
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
          
          round_ctr_reg <= 4'h0;
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

endmodule // aes_keygen

//======================================================================
// EOF aes_keygen.v
//======================================================================
