//======================================================================
//
// test_rcon.v
// -----------
// Simple test module for rcon.
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

//------------------------------------------------------------------
// Simulator directives.
//------------------------------------------------------------------
`timescale 1ns/10ps

module test_rcon();
  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = CLK_HALF_PERIOD * 2;
  

  //----------------------------------------------------------------
  // Registers and Wire declarations.
  //----------------------------------------------------------------
  reg [7 : 0] rcon_reg;
  reg [7 : 0] rcon_new;
  reg         rcon_we;
  reg         rcon_set;
  reg         rcon_next;

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg clk;
  reg reset_n;
  
  
  //----------------------------------------------------------------
  // clk_gen
  //
  // Clock generator process. 
  //----------------------------------------------------------------
  always 
    begin : clk_gen
      #CLK_HALF_PERIOD clk = !clk;
    end // clk_gen
  
    
  //----------------------------------------------------------------
  // sys_monitor
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      #(CLK_PERIOD);      
      $display("rcon_reg = 0x%02x", rcon_reg);
    end

    
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
          rcon_reg        <= 8'h00;
        end
      else
        begin
          if (rcon_we)
            begin
              rcon_reg <= rcon_new;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // rcon_logic
  //
  // Caclulates the rcon value for the different key expansion
  // iterations.
  //----------------------------------------------------------------
  always @*
    begin : rcon_logic
      rcon_new = 8'h00;
      rcon_we  = 0;

      if (rcon_set)
        begin
          rcon_new = 8'h8d;
          rcon_we  = 1;
        end

      if (rcon_next)
        begin
          rcon_new  = ({rcon_reg[6 : 0], 1'b0} ^ (8'h11 & {8{rcon_reg[7]}}));
          rcon_we  = 1;
        end
    end

  
  //----------------------------------------------------------------
  // reset_dut()
  //----------------------------------------------------------------
  task reset_dut();
    begin
      $display("*** Reset asserted ***");
      reset_n = 0;
      #(2 * CLK_PERIOD);
      reset_n = 1;
      $display("*** Reset deasserted ***");
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // run_test()
  //----------------------------------------------------------------
  task run_test();
    begin
      rcon_set  = 1;
      #(2 * CLK_PERIOD);
      rcon_set  = 0;
      #(2 * CLK_PERIOD);

      rcon_next = 1;
      #(256 * CLK_PERIOD);
      rcon_next = 0;
    end
  endtask // run_test
  
  
  //----------------------------------------------------------------
  // init_test()
  //----------------------------------------------------------------
  task init_test();
    begin
      clk       = 0;
      reset_n   = 1;
      rcon_set  = 0;
      rcon_next = 0;
    end
  endtask // init_test

    
  //----------------------------------------------------------------
  // rcon_test
  //
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : rcon_test
      $display("*** rcon simulation started. ***");

      init_test();
      reset_dut();
      run_test();
      
      $display("*** rcon simulation done. ***");
      $finish;
    end // rcon_test

  
endmodule // test_rcon

//======================================================================
// EOF test_rcon.v
//======================================================================
