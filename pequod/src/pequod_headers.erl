%%% @doc Bitcoin headers message parse
%%% Format: varint(count) + count * (80-byte header + 1-byte tx_count)
%%% Ref: ferrous-utils/sync/src/network/messages.rs HeadersMessage
-module(pequod_headers).
-export([parse/1]).

-spec parse(binary()) -> {ok, [binary()]} | {error, term()}.
parse(Binary) ->
    try
        {Count, Consumed} = decode_varint(Binary),
        if Count > 2000 -> {error, too_many_headers};
           true ->
            Rest = binary:part(Binary, Consumed, byte_size(Binary) - Consumed),
            parse_headers(Rest, Count, [])
        end
    catch _:_ -> {error, parse_failed}
    end.

parse_headers(_, 0, Acc) -> {ok, lists:reverse(Acc)};
parse_headers(Binary, N, Acc) when byte_size(Binary) >= 81 ->
    <<Header:80/binary, _TxCount:8, Rest/binary>> = Binary,
    parse_headers(Rest, N - 1, [Header | Acc]);
parse_headers(_, _, _) -> {error, truncated}.

decode_varint(<<16#fd:8, N:16/little, _/binary>>) -> {N, 3};
decode_varint(<<16#fe:8, N:32/little, _/binary>>) -> {N, 5};
decode_varint(<<16#ff:8, N:64/little, _/binary>>) -> {N, 9};
decode_varint(<<N:8, _/binary>>) -> {N, 1}.
