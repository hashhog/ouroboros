%%% Protocol encode/decode round-trip tests
-module(pequod_protocol_tests).
-include_lib("eunit/include/eunit.hrl").

encode_decode_roundtrip_test() ->
    Magic = pequod_chain_params:get_magic(testnet4),
    Payload = <<"hello">>,
    Hdr = pequod_protocol:encode_header(Magic, <<"version">>, Payload),
    ?assertEqual(24, byte_size(Hdr)),
    {ok, Magic, <<"version">>, 5, _Cs} = pequod_protocol:decode_header(Hdr),
    ok.

checksum_test() ->
    Payload = <<1,2,3,4,5>>,
    Cs = pequod_protocol:checksum(Payload),
    ?assertEqual(4, byte_size(Cs)),
    ok.
