//======================================================================
//
// tb_aes_encipher_block.v
// -----------------------
// Testbench for the AES encipher block module.
//
// Test cases from NIST SP 800-38A:
// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
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

`default_nettype none

module tb_aes_encipher_block();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG     = 0;
  parameter DUMP_WAIT = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD = 2 * CLK_HALF_PERIOD;

  parameter AES_128_BIT_KEY = 0;
  parameter AES_256_BIT_KEY = 1;

  parameter AES_DECIPHER = 1'b0;
  parameter AES_ENCIPHER = 1'b1;


  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0]   cycle_ctr;
  reg [31 : 0]   error_ctr;
  reg [31 : 0]   tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;

  reg            tb_next;
  reg            tb_keylen;
  wire           tb_ready;
  wire [3 : 0]   tb_round;
  wire [127 : 0] tb_round_key;

  wire [31 : 0]  tb_sboxw;
  wire [31 : 0]  tb_new_sboxw;

  reg [127 : 0]  tb_block;
  wire [127 : 0] tb_new_block;

  reg [127 : 0] key_mem [0 : 14];


  //----------------------------------------------------------------
  // Assignments.
  //----------------------------------------------------------------
  assign tb_round_key = key_mem[tb_round];


  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  // We need an sbox for the tests.
  aes_sbox sbox(
                .sboxw(tb_sboxw),
                .new_sboxw(tb_new_sboxw)
               );


  // The device under test.
  aes_encipher_block dut(
                         .clk(tb_clk),
                         .reset_n(tb_reset_n),

                         .next(tb_next),

                         .keylen(tb_keylen),
                         .round(tb_round),
                         .round_key(tb_round_key),

                         .sboxw(tb_sboxw),
                         .new_sboxw(tb_new_sboxw),

                         .block(tb_block),
                         .new_block(tb_new_block),
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
  task dump_dut_state;
    begin
      $display("State of DUT");
      $display("------------");
      $display("Interfaces");
      $display("ready = 0x%01x, next = 0x%01x, keylen = 0x%01x",
               dut.ready, dut.next, dut.keylen);
      $display("block     = 0x%032x", dut.block);
      $display("new_block = 0x%032x", dut.new_block);
      $display("");

      $display("Control states");
      $display("round = 0x%01x", dut.round);
      $display("enc_ctrl = 0x%01x, update_type = 0x%01x, sword_ctr = 0x%01x, round_ctr = 0x%01x",
               dut.enc_ctrl_reg, dut.update_type, dut.sword_ctr_reg, dut.round_ctr_reg);
      $display("");

      $display("Internal data values");
      $display("round_key = 0x%016x", dut.round_key);
      $display("sboxw = 0x%08x, new_sboxw = 0x%08x", dut.sboxw, dut.new_sboxw);
      $display("block_w0_reg = 0x%08x, block_w1_reg = 0x%08x, block_w2_reg = 0x%08x, block_w3_reg = 0x%08x",
               dut.block_w0_reg, dut.block_w1_reg, dut.block_w2_reg, dut.block_w3_reg);
      $display("");
      $display("old_block          = 0x%08x", dut.round_logic.old_block);
      $display("shiftrows_block    = 0x%08x", dut.round_logic.shiftrows_block);
      $display("mixcolumns_block   = 0x%08x", dut.round_logic.mixcolumns_block);
      $display("addkey_init_block  = 0x%08x", dut.round_logic.addkey_init_block);
      $display("addkey_main_block  = 0x%08x", dut.round_logic.addkey_main_block);
      $display("addkey_final_block = 0x%08x", dut.round_logic.addkey_final_block);
      $display("block_w0_new = 0x%08x, block_w1_new = 0x%08x, block_w2_new = 0x%08x, block_w3_new = 0x%08x",
               dut.block_new[127 : 096], dut.block_new[095 : 064],
               dut.block_new[063 : 032], dut.block_new[031 : 000]);
      $display("");
    end
  endtask // dump_dut_state


  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("--- Toggle reset.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
      $display("");
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr    = 0;
      error_ctr    = 0;
      tc_ctr       = 0;

      tb_clk       = 0;
      tb_reset_n   = 1;

      tb_next      = 0;
      tb_keylen    = 0;

      tb_block     = {4{32'h00000000}};
    end
  endtask // init_sim


  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0)
        begin
          $display("--- All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("--- %02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
        end
    end
  endtask // display_test_result


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (!tb_ready)
        begin
          #(CLK_PERIOD);
          if (DUMP_WAIT)
            begin
              dump_dut_state();
            end
        end
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // test_ecb_enc()
  //
  // Perform ECB mode encryption test.
  //----------------------------------------------------------------
  task test_ecb_enc(
                    input           key_length,
                    input [127 : 0] block,
                    input [127 : 0] expected);
   begin
     tc_ctr = tc_ctr + 1;

     $display("--- ECB mode test started.");

     // Init the cipher with the given key and length.
     tb_keylen = key_length;

     // Perform encipher operation on the block.
     tb_block = block;
     tb_next = 1;
     #(2 * CLK_PERIOD);
     tb_next = 0;
     #(2 * CLK_PERIOD);

     wait_ready();

     if (tb_new_block == expected)
       begin
         $display("--- Testcase successful.");
         $display("--- Got: 0x%032x", tb_new_block);
       end
     else
       begin
         $display("--- ERROR: Testcase NOT successful.");
         $display("--- Expected: 0x%032x", expected);
         $display("--- Got:      0x%032x", tb_new_block);
         error_ctr = error_ctr + 1;
       end
     $display("--- ECB mode test completed.");
   end
  endtask // ecb_mode_single_block_test


  //----------------------------------------------------------------
  // load_nist128_key
  //----------------------------------------------------------------
  task load_nist128_key;
    begin : load_nist128_key
      key_mem[00] = 128'h2b7e151628aed2a6abf7158809cf4f3c;
      key_mem[01] = 128'ha0fafe1788542cb123a339392a6c7605;
      key_mem[02] = 128'hf2c295f27a96b9435935807a7359f67f;
      key_mem[03] = 128'h3d80477d4716fe3e1e237e446d7a883b;
      key_mem[04] = 128'hef44a541a8525b7fb671253bdb0bad00;
      key_mem[05] = 128'hd4d1c6f87c839d87caf2b8bc11f915bc;
      key_mem[06] = 128'h6d88a37a110b3efddbf98641ca0093fd;
      key_mem[07] = 128'h4e54f70e5f5fc9f384a64fb24ea6dc4f;
      key_mem[08] = 128'head27321b58dbad2312bf5607f8d292f;
      key_mem[09] = 128'hac7766f319fadc2128d12941575c006e;
      key_mem[10] = 128'hd014f9a8c9ee2589e13f0cc8b6630ca6;
      key_mem[11] = 128'h00000000000000000000000000000000;
      key_mem[12] = 128'h00000000000000000000000000000000;
      key_mem[13] = 128'h00000000000000000000000000000000;
      key_mem[14] = 128'h00000000000000000000000000000000;
    end
  endtask // load_nist128_key


  //----------------------------------------------------------------
  // load_nist256_key
  //----------------------------------------------------------------
  task load_nist256_key;
    begin : load_nist256_key
      key_mem[00] = 128'h603deb1015ca71be2b73aef0857d7781;
      key_mem[01] = 128'h1f352c073b6108d72d9810a30914dff4;
      key_mem[02] = 128'h9ba354118e6925afa51a8b5f2067fcde;
      key_mem[03] = 128'ha8b09c1a93d194cdbe49846eb75d5b9a;
      key_mem[04] = 128'hd59aecb85bf3c917fee94248de8ebe96;
      key_mem[05] = 128'hb5a9328a2678a647983122292f6c79b3;
      key_mem[06] = 128'h812c81addadf48ba24360af2fab8b464;
      key_mem[07] = 128'h98c5bfc9bebd198e268c3ba709e04214;
      key_mem[08] = 128'h68007bacb2df331696e939e46c518d80;
      key_mem[09] = 128'hc814e20476a9fb8a5025c02d59c58239;
      key_mem[10] = 128'hde1369676ccc5a71fa2563959674ee15;
      key_mem[11] = 128'h5886ca5d2e2f31d77e0af1fa27cf73c3;
      key_mem[12] = 128'h749c47ab18501ddae2757e4f7401905a;
      key_mem[13] = 128'hcafaaae3e4d59b349adf6acebd10190d;
      key_mem[14] = 128'hfe4890d1e6188d0b046df344706c631e;
    end
  endtask // load_nist256_key


  //----------------------------------------------------------------
  // test_nist_enc_128_1
  //----------------------------------------------------------------
  task test_nist_enc_128_1;
    begin : nist_enc_128_1
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'h6bc1bee22e409f96e93d7e117393172a;
      ciphertext = 128'h3ad77bb40d7a3660a89ecaf32466ef97;

      $display("--- test_nist_enc_128_1: Started.");

      test_ecb_enc(AES_128_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_128_1: Completed.");
      $display("");
    end
  endtask // test_nist_enc_128_1


  //----------------------------------------------------------------
  // test_nist_enc_128_2
  //----------------------------------------------------------------
  task test_nist_enc_128_2;
    begin : nist_enc_128_2
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
      ciphertext = 128'hf5d3d58503b9699de785895a96fdbaaf;

      $display("--- test_nist_enc_128_2: Started.");

      test_ecb_enc(AES_128_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_128_2: Completed.");
      $display("");
    end
  endtask // test_nist_enc_128_2


  //----------------------------------------------------------------
  // test_nist_enc_128_3
  //----------------------------------------------------------------
  task test_nist_enc_128_3;
    begin : nist_enc_128_3
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
      ciphertext = 128'h43b1cd7f598ece23881b00e3ed030688;

      $display("--- test_nist_enc_128_3: Started.");

      test_ecb_enc(AES_128_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_128_3: Completed.");
      $display("");
    end
  endtask // test_nist_enc_128_3


  //----------------------------------------------------------------
  // test_nist_enc_128_4
  //----------------------------------------------------------------
  task test_nist_enc_128_4;
    begin : nist_enc_128_4
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'hf69f2445df4f9b17ad2b417be66c3710;
      ciphertext = 128'h7b0c785e27e8ad3f8223207104725dd4;

      $display("--- test_nist_enc_128_4: Started.");

      test_ecb_enc(AES_128_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_128_4: Completed.");
      $display("");
    end
  endtask // test_nist_enc_128_4


  //----------------------------------------------------------------
  // test_nist_enc_256_1
  //----------------------------------------------------------------
  task test_nist_enc_256_1;
    begin : nist_enc_256_1
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'h6bc1bee22e409f96e93d7e117393172a;
      ciphertext = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;

      $display("--- test_nist_enc_256_1: Started.");

      test_ecb_enc(AES_256_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_256_1: Completed.");
      $display("");
    end
  endtask // test_nist_enc_256_1


  //----------------------------------------------------------------
  // test_nist_enc_256_2
  //----------------------------------------------------------------
  task test_nist_enc_256_2;
    begin : nist_enc_256_2
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'hae2d8a571e03ac9c9eb76fac45af8e51;
      ciphertext = 128'h591ccb10d410ed26dc5ba74a31362870;

      $display("--- test_nist_enc_256_2: Started.");

      test_ecb_enc(AES_256_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_256_2: Completed.");
      $display("");
    end
  endtask // test_nist_enc_256_2


  //----------------------------------------------------------------
  // test_nist_enc_256_3
  //----------------------------------------------------------------
  task test_nist_enc_256_3;
    begin : nist_enc_256_3
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'h30c81c46a35ce411e5fbc1191a0a52ef;
      ciphertext = 128'hb6ed21b99ca6f4f9f153e7b1beafed1d;

      $display("--- test_nist_enc_256_3: Started.");

      test_ecb_enc(AES_256_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_256_3: Completed.");
      $display("");
    end
  endtask // test_nist_enc_256_3


  //----------------------------------------------------------------
  // test_nist_enc_256_4
  //----------------------------------------------------------------
  task test_nist_enc_256_4;
    begin : nist_enc_256_4
      reg [127 : 0] plaintext;
      reg [127 : 0] ciphertext;

      plaintext  = 128'hf69f2445df4f9b17ad2b417be66c3710;
      ciphertext = 128'h23304b7a39f9f3ff067d8d8f9e24ecc7;

      $display("--- test_nist_enc_256_4: Started.");

      test_ecb_enc(AES_256_BIT_KEY, plaintext, ciphertext);
      $display("--- test_nist_enc_256_4: Completed.");
      $display("");
    end
  endtask // test_nist_enc_256_4


  //----------------------------------------------------------------
  // tb_aes_encipher_block
  // The main test functionality.
  //----------------------------------------------------------------
  initial
    begin : tb_aes_encipher_block
      $display("   -= Testbench for aes encipher block started =-");
      $display("     ============================================");
      $display("");

      init_sim();
      reset_dut();

      load_nist128_key();
      test_nist_enc_128_1();
      test_nist_enc_128_2();
      test_nist_enc_128_3();
      test_nist_enc_128_4();

      load_nist256_key();
      test_nist_enc_256_1();
      test_nist_enc_256_2();
      test_nist_enc_256_3();
      test_nist_enc_256_4();

      display_test_result();
      $display("");
      $display("   -= Testbench for aes encipher block completed =-");
      $display("     ============================================");
      $finish;
    end // tb_aes_encipher_block
endmodule // tb_aes_encipher_block

//======================================================================
// EOF tb_aes_encipher_block.v
//======================================================================
