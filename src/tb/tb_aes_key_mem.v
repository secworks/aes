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

  parameter AES_128_NUM_ROUNDS = 10;
  parameter AES_192_NUM_ROUNDS = 12;
  parameter AES_256_NUM_ROUNDS = 14;

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
      $display("key       = 0x%032x", dut.key);
      $display("keylen    = 0x%01x, init = 0x%01x, ready = 0x%01x",
               dut.keylen, dut.init, dut.ready);
      $display("round     = 0x%02x", dut.round);
      $display("round_key = 0x%016x", dut.round_key);
      $display("");

      $display("Internal states:");
      $display("key_mem_ctrl = 0x%01x, round_ctr_reg = 0x%01x, rcon_reg = 0x%01x",
               dut.key_mem_ctrl_reg, dut.round_ctr_reg, dut.rcon_reg);
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
  // dump_dut_memory()
  //----------------------------------------------------------------
  task dump_dut_memory();
    reg [3 : 0] round_nr;
    begin
      for (round_nr = 4'h0 ; round_nr < AES_256_NUM_ROUNDS ; round_nr = round_nr + 1'b1)
        begin
          tb_round = round_nr;
          #(CLK_PERIOD);
          $display("round_key[0x%01x] = 0x%016x", round_nr, tb_round_key);
        end
    end
  endtask // dump_dut_memory


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready();
    begin
      while (!tb_ready)
        begin
          #(CLK_PERIOD);
        end
    end
  endtask // wait_ready



  //----------------------------------------------------------------
  // check_key()
  //
  // Check a given key in the dut key memory against a given
  // expected key.
  //----------------------------------------------------------------
  task check_key(input [3 : 0] key_nr, input [127 : 0] expected);
    begin
      tb_round = key_nr;
      #(CLK_PERIOD);
      if (tb_round_key == expected)
        begin
          $display("key 0x%01x matched expected round key.", key_nr);
        end
      else
        begin
          $display("Error: key 0x%01x did not match expected round key.", key_nr);
          $display("Expected: 0x%016x", expected);
          $display("Got:      0x%016x", tb_round_key);
          error_ctr = error_ctr + 1;
        end
      $display("");
    end
  endtask // dump_dut_memory


  //----------------------------------------------------------------
  // test_key_128()
  //
  // Test 128 bit keys. Due to array problems, the result check
  // is fairly ugly.
  //----------------------------------------------------------------
  task test_key_128(input [255 : 0] key, 
                    input [127 : 0] expected00,
                    input [127 : 0] expected01,
                    input [127 : 0] expected02,
                    input [127 : 0] expected03,
                    input [127 : 0] expected04,
                    input [127 : 0] expected05,
                    input [127 : 0] expected06,
                    input [127 : 0] expected07,
                    input [127 : 0] expected08,
                    input [127 : 0] expected09
                   );
    begin
      $display("Testing with 128-bit key 0x%16x", key[255 : 128]);
      $display("");

      tb_key = key;
      tb_init = 1;
      #(2 * CLK_PERIOD);
      tb_init = 0;
      wait_ready();

      check_key(4'h0, expected00);
      check_key(4'h1, expected01);
      check_key(4'h2, expected02);
      check_key(4'h3, expected03);
      check_key(4'h4, expected04);
      check_key(4'h5, expected05);
      check_key(4'h6, expected06);
      check_key(4'h7, expected07);
      check_key(4'h8, expected08);
      check_key(4'h9, expected09);
    end
  endtask // test_key_128
  

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
      reg [255 : 0] test_key;
      reg [127 : 0] expected00;
      reg [127 : 0] expected01;
      reg [127 : 0] expected02;
      reg [127 : 0] expected03;
      reg [127 : 0] expected04;
      reg [127 : 0] expected05;
      reg [127 : 0] expected06;
      reg [127 : 0] expected07;
      reg [127 : 0] expected08;
      reg [127 : 0] expected09;
      reg [127 : 0] expected10;
      reg [127 : 0] expected11;
      reg [127 : 0] expected12;
      reg [127 : 0] expected13;
      
      $display("   -= Testbench for aes key mem started =-");
      $display("    =====================================");
      $display("");

      init_sim();
      dump_dut_state();
      reset_dut();

      $display("State after reset:");
      dump_dut_state();
      $display("");
      
      #(100 *CLK_PERIOD);

      test_key   = 256'h00000000000000000000000000000000000000000000000000000000000000;
      expected00 = 128'h00000000000000000000000000000000;
      expected01 = 128'h62636363626363636263636362636363; 
      expected02 = 128'h9b9898c9f9fbfbaa9b9898c9f9fbfbaa; 
      expected03 = 128'h90973450696ccffaf2f457330b0fac99; 
      expected04 = 128'hee06da7b876a1581759e42b27e91ee2b; 
      expected05 = 128'h7f2e2b88f8443e098dda7cbbf34b9290; 
      expected06 = 128'hec614b851425758c99ff09376ab49ba7; 
      expected07 = 128'h217517873550620bacaf6b3cc61bf09b; 
      expected08 = 128'h0ef903333ba9613897060a04511dfa9f; 
      expected09 = 128'hb1d4d8e28a7db9da1d7bb3de4c664941; 
      expected10 = 128'hb4ef5bcb3e92e21123e951cf6f8f188e; 

      test_key_128(test_key, expected00, expected01, expected02, expected03, expected04, 
                   expected05, expected06, expected07, expected08, expected09);

      
      display_test_result();
      $display("");
      $display("*** AES core simulation done. ***");
      $finish;
    end // aes_key_mem_test
endmodule // tb_aes_key_mem

//======================================================================
// EOF tb_aes_key_mem.v
//======================================================================

