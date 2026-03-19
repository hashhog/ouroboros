%%% @doc Bitcoin getdata message - requests blocks by inventory
%%% encode([{type, hash}]) where type=2 for block
%%% Ref: ferrous-utils/sync/src/network/messages.rs GetDataMessage
-module(pequod_getdata).
-export([encode/1]).

%% Inventory types: 1=tx, 2=block, 3=filtered_block, 4=compact_block
%% Format: varint(count) + count * (type:4 LE + hash:32)
-spec encode([{non_neg_integer(), binary()}]) -> binary().
encode(Items) when is_list(Items) ->
    Count = length(Items),
    CountBin = encode_varint(Count),
    ItemsBin = iolist_to_binary([<<Type:32/little, Hash:32/binary>> || {Type, Hash} <- Items]),
    <<CountBin/binary, ItemsBin/binary>>.

encode_varint(N) when N < 16#fd -> <<N:8>>;
encode_varint(N) when N =< 16#ffff -> <<16#fd:8, N:16/little>>;
encode_varint(N) when N =< 16#ffffffff -> <<16#fe:8, N:32/little>>;
encode_varint(N) -> <<16#ff:8, N:64/little>>.
