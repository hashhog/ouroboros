%%% @doc Single Bitcoin P2P peer connection - gen_statem
%%% States: connecting | version_sent | handshaking | ready | closed
%%% Desync recovery: if PEQUOD_TRY_RESYNC=1, scan buffer for magic before disconnect
%%% Ref: BLOCK_SYNC_DEBUGGING_GUIDE.md, ferrous-utils/sync/src/network/peer.rs
-module(pequod_peer).
-behaviour(gen_statem).
-export([start_link/3, send_message/2, get_addr/1]).
-export([callback_mode/0, init/1, terminate/3, code_change/4]).
-export([connecting/3, version_sent/3, handshaking/3, ready/3, closed/3]).

-record(data, {
    host :: inet:hostname(),
    port :: inet:port_number(),
    sock :: port() | undefined,
    magic :: binary(),
    parent :: pid(),
    addr :: term(),
    buffer = <<>> :: binary()
}).

start_link(Host, Port, Parent) ->
    gen_statem:start_link(?MODULE, [Host, Port, Parent], []).

send_message(Pid, Msg) ->
    gen_statem:call(Pid, {send, Msg}).

get_addr(Pid) ->
    gen_statem:call(Pid, get_addr).

callback_mode() -> [state_functions, state_enter].

init([Host, Port, Parent]) ->
    Network = application:get_env(pequod, network, testnet4),
    Magic = pequod_chain_params:get_magic(Network),
    Data = #data{host = Host, port = Port, magic = Magic, parent = Parent,
                 addr = {Host, Port}},
    {ok, connecting, Data, [{next_event, internal, connect}]}.

connecting(enter, _OldState, _Data) -> keep_state_and_data;
connecting({call, From}, _Req, _D) -> {keep_state_and_data, [{reply, From, {error, not_ready}}]};
connecting(info, {tcp_closed, _}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), closed}, {next_state, closed, D#data{}};
connecting(info, {tcp_error, _, Reason}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), {error, Reason}}, {next_state, closed, D#data{}};
connecting(internal, connect, #data{host = Host, port = Port, magic = Magic, parent = Parent} = Data) ->
    case gen_tcp:connect(Host, Port, [binary, {active, false}], 10000) of
        {error, Reason} ->
            Parent ! {pequod_peer, self(), {error, Reason}},
            {next_state, closed, Data#data{}};
        {ok, Sock} ->
            gen_tcp:controlling_process(Sock, self()),
            inet:setopts(Sock, [{active, once}]),
            %% Send version message
            AddrRecv = {0, {0,0,0,0}, pequod_chain_params:port(application:get_env(pequod, network, testnet4))},
            AddrFrom = {0, {0,0,0,0}, 0},
            TS = erlang:system_time(second),
            Payload = pequod_version:version_payload(70015, 0, TS, AddrRecv, AddrFrom,
                 rand:uniform(16#ffffffff) band 16#ffffffff,
                 <<"pequod/0.1">>, 0, false),
            Msg = pequod_protocol:encode_header(Magic, <<"version">>, Payload),
            ok = gen_tcp:send(Sock, <<Msg/binary, Payload/binary>>),
            {next_state, version_sent, Data#data{sock = Sock}}
    end.

version_sent(enter, _OldState, _Data) -> keep_state_and_data;
version_sent({call, From}, _Req, _D) -> {keep_state_and_data, [{reply, From, {error, not_ready}}]};
version_sent(info, {tcp_closed, _}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), closed}, {next_state, closed, D#data{}};
version_sent(info, {tcp_error, _, Reason}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), {error, Reason}}, {next_state, closed, D#data{}};
version_sent(info, {tcp, Sock, Data}, #data{buffer = Buf} = D) ->
    inet:setopts(Sock, [{active, once}]),
    NewBuf = <<Buf/binary, Data/binary>>,
    case try_recv_message(D#data{buffer = NewBuf}) of
        {ok, Command, _Payload, Rest} ->
            if Command =:= <<"version">> ->
                   %% Send verack, wait for verack
                   Magic = D#data.magic,
                   VerAck = pequod_protocol:encode_header(Magic, <<"verack">>, <<>>),
                   ok = gen_tcp:send(Sock, VerAck),
                   {next_state, handshaking, D#data{buffer = Rest}};
               true -> {keep_state, D#data{buffer = Rest}}
            end;
        {incomplete, _} -> {keep_state, D#data{buffer = NewBuf}};
        {error, E} -> handle_error(E, D)
    end.

handshaking(enter, _OldState, _Data) -> keep_state_and_data;
handshaking({call, From}, _Req, _D) -> {keep_state_and_data, [{reply, From, {error, not_ready}}]};
handshaking(info, {tcp_closed, _}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), closed}, {next_state, closed, D#data{}};
handshaking(info, {tcp_error, _, Reason}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), {error, Reason}}, {next_state, closed, D#data{}};
handshaking(info, {tcp, Sock, Data}, #data{buffer = Buf, parent = Parent} = D) ->
    inet:setopts(Sock, [{active, once}]),
    NewBuf = <<Buf/binary, Data/binary>>,
    case try_recv_message(D#data{buffer = NewBuf}) of
        {ok, <<"verack">>, _Payload, Rest} ->
            Parent ! {pequod_peer, self(), ready},
            {next_state, ready, D#data{buffer = Rest}};
        {ok, _Cmd, _Payload, Rest} ->
            {keep_state, D#data{buffer = Rest}};
        {incomplete, _} -> {keep_state, D#data{buffer = NewBuf}};
        {error, E} -> handle_error(E, D)
    end.

ready(enter, _OldState, _Data) -> keep_state_and_data;
ready(info, {tcp_closed, _}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), closed}, {next_state, closed, D#data{}};
ready(info, {tcp_error, _, Reason}, #data{parent = Parent} = D) ->
    Parent ! {pequod_peer, self(), {error, Reason}}, {next_state, closed, D#data{}};
ready(info, {tcp, _Sock, Data}, #data{buffer = Buf, parent = Parent} = D) ->
    inet:setopts(D#data.sock, [{active, once}]),
    NewBuf = <<Buf/binary, Data/binary>>,
    case try_recv_message(D#data{buffer = NewBuf}) of
        {ok, Command, Payload, Rest} ->
            Parent ! {pequod_peer, self(), Command, Payload},
            {keep_state, D#data{buffer = Rest}};
        {incomplete, _} -> {keep_state, D#data{buffer = NewBuf}};
        {error, E} -> handle_error(E, D)
    end;
ready({call, From}, {send, Msg}, #data{sock = Sock} = _D) ->
    ok = gen_tcp:send(Sock, Msg),
    {keep_state_and_data, [{reply, From, ok}]};
ready({call, From}, get_addr, #data{addr = Addr} = _D) ->
    {keep_state_and_data, [{reply, From, Addr}]}.

closed(enter, _OldState, _Data) -> keep_state_and_data;
closed({call, From}, _Req, _D) ->
    {keep_state_and_data, [{reply, From, {error, closed}}]}.

terminate(_Reason, _State, #data{sock = Sock, parent = Parent}) ->
    if is_pid(Parent) -> Parent ! {pequod_peer, self(), closed}; true -> ok end,
    if Sock =/= undefined -> catch gen_tcp:close(Sock); true -> ok end,
    ok.
code_change(_V, State, Data, _Extra) -> {ok, State, Data}.

handle_error(E, #data{parent = Parent} = Data) ->
    Parent ! {pequod_peer, self(), {error, E}},
    {next_state, closed, Data}.

-define(RESYNC_SCAN_LIMIT, 1024 * 1024).  %% 1MB - limit scan before giving up

try_recv_message(#data{buffer = Buf, magic = ExpectedMagic} = D) ->
    case byte_size(Buf) >= 24 of
        true ->
            <<Header:24/binary, _/binary>> = Buf,
            case pequod_protocol:decode_header(Header) of
                {ok, PacketMagic, Cmd, Size, HeaderChecksum} ->
                    Total = 24 + Size,
                    if byte_size(Buf) >= Total ->
                           <<_H:24/binary, Payload:Size/binary, Rest/binary>> = Buf,
                           Sum = pequod_protocol:checksum(Payload),
                           if PacketMagic =/= ExpectedMagic ->
                                  try_resync_or_error(invalid_magic, D);
                              Sum =/= HeaderChecksum -> {error, checksum_mismatch};
                              true -> {ok, Cmd, Payload, Rest}
                           end;
                       true -> {incomplete, Total}
                    end;
                {error, {payload_size_exceeded, _, _}} = E ->
                    try_resync_or_error(E, D);
                {error, _} = E -> E
            end;
        false -> {incomplete, 24}
    end.

try_resync_or_error(Error, #data{buffer = Buf, magic = Magic}) ->
    case try_resync_enabled() of
        true ->
            case scan_for_magic(Buf, Magic) of
                {ok, ResyncedBuf} when byte_size(ResyncedBuf) >= 24 ->
                    try_recv_message(#data{buffer = ResyncedBuf, magic = Magic});
                {ok, _} -> {error, Error};  %% Resynced but not enough data
                not_found -> {error, Error}
            end;
        false -> {error, Error}
    end.

try_resync_enabled() ->
    case application:get_env(pequod, try_resync) of
        {ok, true} -> true;
        _ -> os:getenv("PEQUOD_TRY_RESYNC") =:= "1"
    end.

%% Scan buffer for 4-byte magic; if found, return buffer starting at magic. Limit scan to 1MB.
scan_for_magic(Buf, Magic) when byte_size(Magic) =:= 4 ->
    ScanLen = min(byte_size(Buf), ?RESYNC_SCAN_LIMIT),
    ScanBuf = binary:part(Buf, 0, ScanLen),
    case binary:match(ScanBuf, Magic) of
        {Pos, 4} -> {ok, binary:part(Buf, Pos, byte_size(Buf) - Pos)};
        nomatch -> not_found
    end.
