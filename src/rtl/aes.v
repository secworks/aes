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
  parameter ADDR_NAME0       = 8'h00;
  parameter ADDR_NAME1       = 8'h01;
  parameter ADDR_VERSION     = 8'h02;

  parameter ADDR_CTRL        = 8'h08;
  parameter CTRL_INIT_BIT    = 0;
  parameter CTRL_NEXT_BIT    = 1;

  parameter ADDR_STATUS      = 8'h09;
  parameter STATUS_READY_BIT = 0;
  parameter STATUS_VALID_BIT = 1;
                             
  parameter ADDR_BLOCK0    = 8'h10;
  parameter ADDR_BLOCK1    = 8'h11;
  parameter ADDR_BLOCK2    = 8'h12;
  parameter ADDR_BLOCK3    = 8'h13;
                             
  parameter ADDR_RESULT0   = 8'h20;
  parameter ADDR_RESULT1   = 8'h21;
  parameter ADDR_RESULT2   = 8'h22;
  parameter ADDR_RESULT3   = 8'h23;

  parameter CORE_NAME0     = 32'h6165732d; // "aes-"
  parameter CORE_NAME1     = 32'h31323820; // "128 "
  parameter CORE_VERSION   = 32'h302e3530; // "0.50"

  
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg encdec_reg;
  reg next_reg;
  reg ctrl_we;
  
  reg ready_reg;

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

  reg [128 : 0] result_reg;

  reg result_valid_reg;

  
  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_data_out;
  reg            tmp_error;
  
  wire           core_encdec;
  wire           core_next;
  wire           core_ready;
  wire [255 : 0] core_key;
  wire           core_load_key;
  wire [127 : 0] core_block;
  wire [127 : 0] core_results;
  wire           core_results_valid;
  
  
  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign data_out = tmp_data_out;
  assign error    = tmp_error;
  
  assign core_key = {key3_reg, key2_reg, key1_reg, key0_reg};
  
             
  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_core core(
                   .clk(clk),
                   .reset_n(reset_n),
                   
                   .encdec(core_encdec),
                   .next(core_next),
                   .ready(core_ready),

                   .key(core_key),
                   .load_key(core_load_key),
                   
                   .block(core_block),
                   .result(core_results),
                   .result_valid(core_results_valid)
                  );
  
  
  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin
      if (!reset_n)
        begin

        end
      else
        begin
          ready_reg        <= core_ready;
          result_valid_reg <= core_results_valid;
          
        end
    end // reg_update


  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  always @*
    begin : api
      tmp_data_out = 32'h00000000;
      tmp_error    = 0;
      
      if (cs)
        begin
          if (write_read)
            begin
              case (address)
                // Write operations.
                
                default:
                  begin
                    tmp_error = 1;
                  end
              endcase // case (address)
            end // if (write_read)

          else
            begin
              case (address)
                // Read operations.
                ADDR_NAME0:
                  begin
                    tmp_data_out = CORE_NAME0;
                  end
                
                ADDR_NAME1:
                  begin
                    tmp_data_out = CORE_NAME1;
                  end

                ADDR_VERSION:
                  begin
                    tmp_data_out = CORE_VERSION;
                  end
                
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
