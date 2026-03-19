%%% @doc Chain parameters for Bitcoin networks (testnet4, mainnet, etc.)
-module(pequod_chain_params).
-export([get_magic/1, genesis_hash/1, genesis_timestamp/1, genesis_bits/0, port/1]).

-define(MAGIC_TESTNET4, <<16#1c, 16#16, 16#3f, 16#28>>).
-define(MAGIC_MAINNET,  <<16#f9, 16#be, 16#b4, 16#d9>>).
-define(MAGIC_TESTNET,  <<16#0b, 16#11, 16#09, 16#07>>).
-define(PORT_TESTNET4,  48333).
-define(PORT_MAINNET,   8333).
-define(GENESIS_HASH_TESTNET4,
    <<16#43, 16#f0, 16#8b, 16#da, 16#b0, 16#50, 16#e3, 16#5b,
      16#56, 16#7c, 16#86, 16#4b, 16#91, 16#f4, 16#7f, 16#50,
      16#ae, 16#72, 16#5a, 16#e2, 16#de, 16#53, 16#bc, 16#fb,
      16#ba, 16#f2, 16#84, 16#da, 16#00, 16#00, 16#00, 16#00>>).
-define(GENESIS_TIMESTAMP_TESTNET4, 1714777860).
-define(GENESIS_BITS, 16#1d00ffff).

get_magic(testnet4) -> ?MAGIC_TESTNET4;
get_magic(mainnet)  -> ?MAGIC_MAINNET;
get_magic(testnet)  -> ?MAGIC_TESTNET;
get_magic(_)        -> ?MAGIC_TESTNET4.

genesis_hash(testnet4) -> ?GENESIS_HASH_TESTNET4;
genesis_hash(_)        -> ?GENESIS_HASH_TESTNET4.

genesis_timestamp(testnet4) -> ?GENESIS_TIMESTAMP_TESTNET4;
genesis_timestamp(_)        -> ?GENESIS_TIMESTAMP_TESTNET4.

genesis_bits() -> ?GENESIS_BITS.

port(testnet4) -> ?PORT_TESTNET4;
port(mainnet)  -> ?PORT_MAINNET;
port(testnet)  -> ?PORT_TESTNET4;
port(_)        -> ?PORT_TESTNET4.
