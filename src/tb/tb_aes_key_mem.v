//======================================================================
//
// tb_aes_key_mem.v
// ----------------
// Testbench for the AES key memory module.
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

//------------------------------------------------------------------
// Simulator directives.
//------------------------------------------------------------------
`timescale 1ns/100ps


//------------------------------------------------------------------
// Test module.
//------------------------------------------------------------------
module tb_aes_key_mem();
  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD = 2 * CLK_HALF_PERIOD;

  parameter AES_128_BIT_KEY = 2'h0;
  parameter AES_192_BIT_KEY = 2'h1;
  parameter AES_256_BIT_KEY = 2'h2;

  parameter AES_DECIPHER = 1'b0;
  parameter AES_ENCIPHER = 1'b1;

  
  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg [255 : 0]  tb_key;
  reg [1 : 0]    tb_keylen;
  reg            tb_init;
  reg [3 : 0]    tb_round;
  wire [127 : 0] tb_round_key;
  wire           tb_ready;
  
  
  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  aes_key_mem dut(
                  .clk(tb_clk),
                  .reset_n(tb_reset_n),

                  .key(tb_key),
                  .keylen(tb_keylen),
                  .init(tb_init),

                  .round(tb_round),
                  .round_key(tb_round_key),
                  .ready(tb_ready)
                 );
  

  //----------------------------------------------------------------
  // clk_gen
  //
  // Always running clock generator process.
  //----------------------------------------------------------------
  always 
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end // clk_gen
    

  //----------------------------------------------------------------
  // sys_monitor()
  //
  // An always running process that creates a cycle counter and
  // conditionally displays information about the DUT.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      cycle_ctr = cycle_ctr + 1;
      #(CLK_PERIOD);
      if (DEBUG)
        begin
          dump_dut_state();
        end
    end

  
  //----------------------------------------------------------------
  // dump_dut_state()
  //
  // Dump the state of the dump when needed.
  //----------------------------------------------------------------
  task dump_dut_state();
    begin
      $display("State of DUT");
      $display("------------");
      $display("Inputs and outputs:");
      $display("key = 0x%032x" % dut.key);
      $display("keylen = 0x1x, init = 0x%01x, ready = 0x%01x" % dut.keylen, 
               dut.init, dut.ready);
      $display("");

      $display("round     = 0x%02x" % dut.round);
      $display("round_key = 0x%016x" % dut.round_key);
      $display("");
    end
  endtask // dump_dut_state


  
  //----------------------------------------------------------------
  // dump_mem()
  //
  // Dump the contents of the key memory in the dut.
  //----------------------------------------------------------------
  task dump_mem();
    begin
      $display("State of key mem");
      $display("----------------");
      $display("");
    end
  endtask // dump_mem
  
  
  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut();
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut

  
  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim();
    begin
      cycle_ctr = 0;
      error_ctr = 0;
      tc_ctr    = 0;
      
      tb_clk     = 0;
      tb_reset_n = 1;
      tb_key     = {8{32'h00000000}};
      tb_keylen  = 2'h0;
      tb_init    = 0;
      tb_round   = 4'h0;
    end
  endtask // init_sim

  
  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result();
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d tests completed - %02d test cases did not complete successfully.", 
                   tc_ctr, error_ctr);
        end
    end
  endtask // display_test_result
                         
    
  //----------------------------------------------------------------
  // aes_key_mem_test
  // The main test functionality. 
  //----------------------------------------------------------------
  initial
    begin : aes_key_mem_test
      reg [255 : 0] aes128_key0;
      reg [255 : 0] aes128_key1;
      reg [255 : 0] aes128_key2;

      $display("   -= Testbench for aes key mem started =-");
      $display("    =====================================");
      $display("");

      init_sim();
      dump_dut_state();
      reset_dut();

      #(100 *CLK_PERIOD);

      dump_dut_state();
      
      display_test_result();
      $display("");
      $display("*** AES core simulation done. ***");
      $finish;
    end // aes_key_mem_test
endmodule // tb_aes_key_mem

//======================================================================
// EOF tb_aes_key_mem.v
//======================================================================

