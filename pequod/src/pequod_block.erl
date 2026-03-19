%%% @doc Bitcoin block parse - extract header and transaction data
%%% Block format: header(80) + varint(tx_count) + txs
%%% parse(Binary) -> {ok, #{header => <<80>>, txs => [TxBin]}}
%%% For minimal validation we extract header; txs as list of raw binaries.
-module(pequod_block).
-export([parse/1, header_hash/1, header_prev_hash/1]).

-spec parse(binary()) -> {ok, #{header => binary(), txs => [binary()], full => binary()}} | {error, term()}.
parse(Binary) when byte_size(Binary) >= 81 ->
    try
        <<Header:80/binary, Rest/binary>> = Binary,
        {_TxCount, Consumed} = decode_varint(Rest),
        TxPayload = binary:part(Rest, Consumed, byte_size(Rest) - Consumed),
        %% Return full block for storage; txs as single chunk for spec compliance
        {ok, #{header => Header, txs => [TxPayload], full => Binary}}
    catch _:_ -> {error, parse_failed}
    end;
parse(_) -> {error, too_short}.

decode_varint(<<16#fd:8, N:16/little, _/binary>>) -> {N, 3};
decode_varint(<<16#fe:8, N:32/little, _/binary>>) -> {N, 5};
decode_varint(<<16#ff:8, N:64/little, _/binary>>) -> {N, 9};
decode_varint(<<N:8, _/binary>>) -> {N, 1}.

header_hash(<<Header:80/binary>>) ->
    crypto:hash(sha256, crypto:hash(sha256, Header)).

header_prev_hash(<<_:4/binary, PrevHash:32/binary, _/binary>>) -> PrevHash.
