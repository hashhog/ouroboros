%%% @doc Bitcoin getheaders message encode
%%% Format: version(4 LE) + varint(count) + count*32 + hash_stop(32)
%%% Ref: ferrous-utils/sync/src/network/messages.rs GetHeadersMessage
-module(pequod_getheaders).
-export([encode/3]).

-spec encode(non_neg_integer(), [binary()], binary()) -> binary().
encode(Version, LocatorHashes, HashStop) when is_list(LocatorHashes), byte_size(HashStop) =:= 32 ->
    Count = length(LocatorHashes),
    CountBin = encode_varint(Count),
    HashesBin = iolist_to_binary(LocatorHashes),
    <<Version:32/little, CountBin/binary, HashesBin/binary, HashStop:32/binary>>.

encode_varint(N) when N < 16#fd -> <<N:8>>;
encode_varint(N) when N =< 16#ffff -> <<16#fd:8, N:16/little>>;
encode_varint(N) when N =< 16#ffffffff -> <<16#fe:8, N:32/little>>;
encode_varint(N) -> <<16#ff:8, N:64/little>>.
