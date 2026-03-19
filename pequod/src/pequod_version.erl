%%% @doc Bitcoin P2P version and verack messages
%%% Reference: bitcoin protocol.h, ferrous-utils/sync/src/network/messages.rs
-module(pequod_version).
-export([version_payload/9, verack_payload/0, parse_version/1]).

%% Version message payload structure (all LE unless noted):
%% version(4), services(8), timestamp(8), addr_recv(26), addr_from(26),
%% nonce(8), varint(user_agent_len), user_agent, start_height(4), relay(1) for 70001+

%% Network address: services(8) + ip(16) + port(2 big-endian) = 26 bytes
%% IPv4-mapped: ::ffff:a.b.c.d => 00..00 ff ff a b c d
serialize_addr(Services, IP, Port) when tuple_size(IP) =:= 4 ->
    <<A, B, C, D>> = <<(element(1, IP)):8, (element(2, IP)):8, (element(3, IP)):8, (element(4, IP)):8>>,
    IP6 = <<0:80, 16#ffff:16, A:8, B:8, C:8, D:8>>,
    <<Services:64/little, IP6:16/binary, Port:16/big>>.

-spec version_payload(integer(), non_neg_integer(), integer(), tuple(), tuple(),
                     non_neg_integer(), binary(), integer(), boolean()) -> binary().
version_payload(Version, Services, Timestamp, AddrRecv, AddrFrom, Nonce, UserAgent, StartHeight, Relay) ->
    {ARServices, ARIP, ARPort} = AddrRecv,
    {AFServices, AFIP, AFPort} = AddrFrom,
    AddrRecvBin = serialize_addr(ARServices, ARIP, ARPort),
    AddrFromBin = serialize_addr(AFServices, AFIP, AFPort),
    UALen = byte_size(UserAgent),
    UALenVarint = encode_varint(UALen),
    RelayByte = case Version >= 70001 andalso Relay of true -> <<1>>; _ -> <<>> end,
    <<Version:32/little, Services:64/little, Timestamp:64/little,
      AddrRecvBin:26/binary, AddrFromBin:26/binary, Nonce:64/little,
      UALenVarint/binary, UserAgent/binary, StartHeight:32/little, RelayByte/binary>>.

verack_payload() -> <<>>.

parse_version(Data) ->
    try
        <<Version:32/little, Services:64/little, Timestamp:64/little,
          _AddrRecv:26/binary, _AddrFrom:26/binary, Nonce:64/little, Rest/binary>> = Data,
        {UALen, Consumed} = decode_varint(Rest),
        <<UA:UALen/binary, Rest2/binary>> = binary:part(Rest, Consumed, byte_size(Rest) - Consumed),
        StartHeight = case Rest2 of
            <<SH:32/little, _/binary>> -> SH;
            _ -> 0
        end,
        {ok, #{version => Version, services => Services, timestamp => Timestamp,
               nonce => Nonce, user_agent => UA, start_height => StartHeight}}
    catch _:_ -> {error, parse_failed}
    end.

encode_varint(N) when N < 16#fd -> <<N:8>>;
encode_varint(N) when N =< 16#ffff -> <<16#fd:8, N:16/little>>;
encode_varint(N) when N =< 16#ffffffff -> <<16#fe:8, N:32/little>>;
encode_varint(N) -> <<16#ff:8, N:64/little>>.

decode_varint(<<16#fd:8, N:16/little, _/binary>>) -> {N, 3};
decode_varint(<<16#fe:8, N:32/little, _/binary>>) -> {N, 5};
decode_varint(<<16#ff:8, N:64/little, _/binary>>) -> {N, 9};
decode_varint(<<N:8, _/binary>>) -> {N, 1}.
