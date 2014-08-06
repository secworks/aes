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
  parameter DEBUG = 1;
  parameter SHOW_SBOX = 0;

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
  reg            tb_keylen;
  reg            tb_init;
  reg [3 : 0]    tb_round;
  wire [127 : 0] tb_round_key;
  wire           tb_ready;

  wire [31 : 0]  tb_sboxw;
  wire [31 : 0]  tb_new_sboxw;

  
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
                  .ready(tb_ready),

                  .sboxw(tb_sboxw),
                  .new_sboxw(tb_new_sboxw)
                 );

  // The DUT requirees Sboxes.
  aes_sbox sbox(.sboxw(tb_sboxw), .new_sboxw(tb_new_sboxw));
  

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
      $display("key_mem_ctrl = 0x%01x, round_key_update = 0x%01x, round_ctr_reg = 0x%01x, rcon_reg = 0x%01x",
               dut.key_mem_ctrl_reg, dut.round_key_update, dut.round_ctr_reg, dut.rcon_reg);

      $display("prev_key0_reg = 0x%016x, prev_key0_new = 0x%016x, prev_key0_we = 0x%01x",
               dut.prev_key0_reg, dut.prev_key0_new, dut.prev_key0_we);
      $display("prev_key1_reg = 0x%016x, prev_key1_new = 0x%016x, prev_key1_we = 0x%01x",
               dut.prev_key1_reg, dut.prev_key1_new, dut.prev_key1_we);

      $display("w0 = 0x%04x, w1 = 0x%04x, w2 = 0x%04x, w3 = 0x%04x",
               dut.round_key_gen.w0, dut.round_key_gen.w1, 
               dut.round_key_gen.w2, dut.round_key_gen.w3);
      $display("sboxw = 0x%04x, new_sboxw = 0x%04x, rconw = 0x%04x",
               dut.sboxw, dut.new_sboxw, dut.round_key_gen.rconw);
      $display("key_mem_new = 0x%016x", dut.key_mem_new);
      $display("");

      if (SHOW_SBOX)
        begin
          $display("Sbox functionality:");
          $display("sboxw = 0x%08x", sbox.sboxw);
          $display("tmp_new_sbox0 = 0x%02x, tmp_new_sbox1 = 0x%02x, tmp_new_sbox2 = 0x%02x, tmp_new_sbox3",
                   sbox.tmp_new_sbox0, sbox.tmp_new_sbox1, sbox.tmp_new_sbox2, sbox.tmp_new_sbox3);
          $display("new_sboxw = 0x%08x", sbox.new_sboxw);
          $display("");
        end
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
      tb_keylen  = 0;
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
          $display("** key 0x%01x matched expected round key.", key_nr);
          $display("** Got:      0x%016x **", tb_round_key);
        end
      else
        begin
          $display("** Error: key 0x%01x did not match expected round key. **", key_nr);
          $display("** Expected: 0x%016x **", expected);
          $display("** Got:      0x%016x **", tb_round_key);
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
                    input [127 : 0] expected09,
                    input [127 : 0] expected10
                   );
    begin
      $display("** Testing with 128-bit key 0x%16x", key[255 : 128]);
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
      check_key(4'ha, expected10);

      tc_ctr = tc_ctr + 1;
    end
  endtask // test_key_128


  //----------------------------------------------------------------
  // test_key_256()
  //
  // Test 256 bit keys. Due to array problems, the result check
  // is fairly ugly.
  //----------------------------------------------------------------
  task test_key_256(input [255 : 0] key,
                    input [127 : 0] expected00,
                    input [127 : 0] expected01,
                    input [127 : 0] expected02,
                    input [127 : 0] expected03,
                    input [127 : 0] expected04,
                    input [127 : 0] expected05,
                    input [127 : 0] expected06,
                    input [127 : 0] expected07,
                    input [127 : 0] expected08,
                    input [127 : 0] expected09,
                    input [127 : 0] expected10,
                    input [127 : 0] expected11,
                    input [127 : 0] expected12,
                    input [127 : 0] expected13,
                    input [127 : 0] expected14
                   );
    begin
      $display("** Testing with 256-bit key 0x%32x", key[255 : 000]);
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
      check_key(4'ha, expected10);
      check_key(4'hb, expected11);
      check_key(4'hc, expected12);
      check_key(4'hd, expected13);
      check_key(4'he, expected14);

      tc_ctr = tc_ctr + 1;
    end
  endtask // test_key_256
  

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
      reg [255 : 0] key128_0;
      reg [255 : 0] key128_1;
      reg [255 : 0] key256_0;

      reg [127 : 0] expected_00;
      reg [127 : 0] expected_01;
      reg [127 : 0] expected_02;
      reg [127 : 0] expected_03;
      reg [127 : 0] expected_04;
      reg [127 : 0] expected_05;
      reg [127 : 0] expected_06;
      reg [127 : 0] expected_07;
      reg [127 : 0] expected_08;
      reg [127 : 0] expected_09;
      reg [127 : 0] expected_10;
      reg [127 : 0] expected_11;
      reg [127 : 0] expected_12;
      reg [127 : 0] expected_13;
      reg [127 : 0] expected_14;
      
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

      key128_0      = 256'h00000000000000000000000000000000000000000000000000000000000000;
      expected_00 = 128'h00000000000000000000000000000000;
      expected_01 = 128'h62636363626363636263636362636363;
      expected_02 = 128'h9b9898c9f9fbfbaa9b9898c9f9fbfbaa;
      expected_03 = 128'h90973450696ccffaf2f457330b0fac99;
      expected_04 = 128'hee06da7b876a1581759e42b27e91ee2b;
      expected_05 = 128'h7f2e2b88f8443e098dda7cbbf34b9290;
      expected_06 = 128'hec614b851425758c99ff09376ab49ba7;
      expected_07 = 128'h217517873550620bacaf6b3cc61bf09b;
      expected_08 = 128'h0ef903333ba9613897060a04511dfa9f;
      expected_09 = 128'hb1d4d8e28a7db9da1d7bb3de4c664941;
      expected_10 = 128'hb4ef5bcb3e92e21123e951cf6f8f188e;

      test_key_128(key128_0,
                   expected_00, expected_01, expected_02, expected_03,
                   expected_04, expected_05, expected_06, expected_07,
                   expected_08, expected_09, expected_10);

      key256_0      = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;

      expected_00 = 128'h000102030405060708090a0b0c0d0e0f;
      expected_01 = 128'h101112131415161718191a1b1c1d1e1f;
      expected_02 = 128'ha573c29fa176c498a97fce93a572c09c;
      expected_03 = 128'h1651a8cd0244beda1a5da4c10640bade;
      expected_04 = 128'hae87dff00ff11b68a68ed5fb03fc1567;
      expected_05 = 128'h6de1f1486fa54f9275f8eb5373b8518d;
      expected_06 = 128'hc656827fc9a799176f294cec6cd5598b;
      expected_07 = 128'h3de23a75524775e727bf9eb45407cf39;
      expected_08 = 128'h0bdc905fc27b0948ad5245a4c1871c2f;
      expected_09 = 128'h45f5a66017b2d387300d4d33640a820a;
      expected_10 = 128'h7ccff71cbeb4fe5413e6bbf0d261a7df;
      expected_11 = 128'hf01afafee7a82979d7a5644ab3afe640;
      expected_12 = 128'h2541fe719bf500258813bbd55a721c0a;
      expected_13 = 128'h4e5a6699a9f24fe07e572baacdf8cdea;
      expected_14 = 128'h24fc79ccbf0979e9371ac23c6d68de36;

      test_key_256(key256_0,
                   expected_00, expected_01, expected_02, expected_03,
                   expected_04, expected_05, expected_06, expected_07,
                   expected_08, expected_09, expected_10, expected_11,
                   expected_12, expected_13, expected_14);
      
      display_test_result();
      $display("");
      $display("*** AES core simulation done. ***");
      $finish;
    end // aes_key_mem_test
endmodule // tb_aes_key_mem

//======================================================================
// EOF tb_aes_key_mem.v
//======================================================================

