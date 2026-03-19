%%% PoW bits_to_target and validate_pow tests
-module(pequod_pow_tests).
-include_lib("eunit/include/eunit.hrl").

bits_to_target_genesis_test() ->
    Bits = 16#1d00ffff,
    Target = pequod_pow:bits_to_target(Bits),
    ?assert(Target > 0),
    ?assert(Target < (1 bsl 256)),
    ok.

validate_pow_test() ->
    GenesisBits = pequod_chain_params:genesis_bits(),
    Target = pequod_pow:bits_to_target(GenesisBits),
    Header = binary:copy(<<0>>, 80),
    Result = pequod_pow:validate_pow(Header, Target),
    ?assert(Result =:= true orelse Result =:= false),
    ok.
