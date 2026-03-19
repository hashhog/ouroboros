%%% @doc Peer manager: seeds, drain_peers, maintain connections
%%% 1. gen_server: maintain list of connected peers (pequod_peer Pids)
%%% 2. Seeds: DNS + hardcoded IPv4 from BITCOIN_ERLANG_IMPLEMENTATION_GUIDE.md
%%% 3. drain_peers/0 -> [{Addr, Pid}] for ready peers
%%% 4. maintain_connections/0: ensure >= N (e.g. 8) connections
%%% 5. On peer exit: remove, blacklist for T sec on desync (PEQUOD_DESYNC_BLACKLIST_SECS)
%%% Ref: ferrous-utils/sync/src/network/peer_manager.rs
-module(pequod_peer_manager).
-behaviour(gen_server).
-export([start_link/0, drain_peers/0, maintain_connections/0, request_peer/1, release_peer/2, forward_to/2,
         register_block_sink/1, unregister_block_sink/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(TARGET_PEERS, 8).
-define(DEFAULT_DESYNC_BLACKLIST_SECS, 30).

%% Seeds: DNS + hardcoded IPv4 from guide
-define(SEEDS_TESTNET4, [
    {"seed.testnet4.bitcoin.sprovoost.nl", 48333},
    {"seed.testnet4.wiz.biz", 48333},
    {"51.158.61.33", 48333},
    {"35.201.167.154", 48333},
    {"103.165.192.211", 48333},
    {"103.99.170.202", 48333},
    {"54.76.27.166", 48333},
    {"168.119.150.247", 48333},
    {"103.99.168.213", 48333},
    {"158.220.90.103", 48333},
    {"209.146.50.203", 48333},
    {"18.189.156.102", 48333},
    {"208.73.202.78", 48333},
    {"103.165.192.210", 48333}
]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

drain_peers() ->
    gen_server:call(?MODULE, drain_peers).

maintain_connections() ->
    gen_server:cast(?MODULE, maintain_connections).

request_peer(Requester) ->
    gen_server:call(?MODULE, {request_peer, Requester}).

release_peer(PeerPid, Requester) ->
    gen_server:cast(?MODULE, {release_peer, PeerPid, Requester}).

forward_to(PeerPid, Requester) ->
    gen_server:cast(?MODULE, {forward_to, PeerPid, Requester}).

register_block_sink(Pid) ->
    gen_server:cast(?MODULE, {register_block_sink, Pid}).

unregister_block_sink() ->
    gen_server:cast(?MODULE, unregister_block_sink).

init([]) ->
    self() ! maintain,
    {ok, #{peers => [], blacklist => [], assigned => #{}, block_sink => undefined}}.

handle_call(drain_peers, _From, #{peers := Peers} = S) ->
    Ready = [{{Host, Port}, Pid} || {Pid, {Host, Port}, ready} <- Peers],
    {reply, Ready, S};
handle_call({request_peer, Requester}, _From, #{peers := Peers, assigned := Assigned} = S) ->
    Ready = [{Pid, Addr} || {Pid, Addr, ready} <- Peers],
    Unassigned = [P || {P, _} <- Ready, not maps:is_key(P, Assigned)],
    case Unassigned of
        [Pid | _] ->
            {reply, {ok, Pid}, S#{assigned => Assigned#{Pid => Requester}}};
        [] -> {reply, {error, no_peers}, S}
    end;
handle_call(_, _From, S) -> {reply, {error, unknown}, S}.

handle_cast({release_peer, Pid, _Requester}, #{assigned := Assigned} = S) ->
    {noreply, S#{assigned => maps:remove(Pid, Assigned)}};
handle_cast({forward_to, Pid, Requester}, #{assigned := Assigned} = S) ->
    {noreply, S#{assigned => Assigned#{Pid => Requester}}};
handle_cast({register_block_sink, Pid}, S) ->
    {noreply, S#{block_sink => Pid}};
handle_cast(unregister_block_sink, S) ->
    {noreply, S#{block_sink => undefined}};
handle_cast(maintain_connections, S) ->
    S2 = do_maintain(S),
    {noreply, S2};
handle_cast(_, S) -> {noreply, S}.

handle_info(maintain, S) ->
    S2 = do_maintain(S),
    erlang:send_after(5000, self(), maintain),
    {noreply, S2};
handle_info({pequod_peer, Pid, Command, Payload}, #{assigned := Assigned, block_sink := BlockSink} = S) when is_binary(Command) ->
    case maps:find(Pid, Assigned) of
        {ok, Requester} -> Requester ! {pequod_peer, Pid, Command, Payload};
        error -> ok
    end,
    if Command =:= <<"block">>, is_pid(BlockSink) ->
           BlockSink ! {pequod_peer, Pid, <<"block">>, Payload};
       true -> ok
    end,
    {noreply, S};
handle_info({pequod_peer, Pid, ready}, #{peers := Peers} = S) ->
    Addr = case pequod_peer:get_addr(Pid) of
        {ok, A} -> A;
        _ -> {unknown, 0}
    end,
    Peers2 = case lists:keyfind(Pid, 1, Peers) of
        {Pid, _Addr, connecting} -> lists:keyreplace(Pid, 1, Peers, {Pid, Addr, ready});
        _ -> [{Pid, Addr, ready} | [P || {P, _, _} <- Peers, P =/= Pid]]
    end,
    {noreply, S#{peers => Peers2}};
handle_info({pequod_peer, Pid, closed}, #{peers := Peers, block_sink := BlockSink} = S) ->
    if is_pid(BlockSink) -> BlockSink ! {pequod_peer, Pid, closed}; true -> ok end,
    Peers2 = [E || {P, _, _} = E <- Peers, P =/= Pid],
    {noreply, S#{peers => Peers2}};
handle_info({pequod_peer, Pid, {error, Reason}}, #{peers := Peers} = S) ->
    Addr = case lists:keyfind(Pid, 1, Peers) of
        {Pid, A, _} -> A;
        _ -> case pequod_peer:get_addr(Pid) of {ok, A} -> A; _ -> undefined end
    end,
    S2 = case is_desync_error(Reason) andalso Addr =/= undefined of
        true ->
            Blacklist = maps:get(blacklist, S, #{}),
            Secs = desync_blacklist_secs(),
            Until = erlang:monotonic_time(second) + Secs,
            S#{blacklist => Blacklist#{Addr => Until}};
        false -> S
    end,
    Peers2 = [E || {P, _, _} = E <- Peers, P =/= Pid],
    {noreply, S2#{peers => Peers2}};
handle_info({'DOWN', _MRef, process, Pid, _}, #{peers := Peers} = S) ->
    Peers2 = [E || {P, _, _} = E <- Peers, P =/= Pid],
    {noreply, S#{peers => Peers2}};
handle_info(_, S) -> {noreply, S}.

do_maintain(#{peers := Peers} = S) ->
    Blacklist = prune_blacklist(maps:get(blacklist, S, #{})),
    S2 = S#{blacklist => Blacklist},
    ReadyCount = length([1 || {_, _, ready} <- Peers]),
    Target = target_peers(),
    if ReadyCount < Target -> try_connect(S2);
       true -> S2
    end.

prune_blacklist(Blacklist) ->
    Now = erlang:monotonic_time(second),
    maps:filter(fun(_, Until) -> Now >= Until end, Blacklist).

target_peers() ->
    case application:get_env(pequod, target_peers) of
        {ok, N} when is_integer(N), N > 0 -> N;
        _ -> case os:getenv("PEQUOD_TARGET_PEERS") of
            false -> ?TARGET_PEERS;
            V -> case string:to_integer(V) of {N, _} when N > 0 -> N; _ -> ?TARGET_PEERS end
        end
    end.

desync_blacklist_secs() ->
    case application:get_env(pequod, desync_blacklist_secs) of
        {ok, N} when is_integer(N), N >= 0 -> N;
        _ -> case os:getenv("PEQUOD_DESYNC_BLACKLIST_SECS") of
            false -> ?DEFAULT_DESYNC_BLACKLIST_SECS;
            V -> case string:to_integer(V) of {N, _} when N >= 0 -> N; _ -> ?DEFAULT_DESYNC_BLACKLIST_SECS end
        end
    end.

is_desync_error(invalid_magic) -> true;
is_desync_error(checksum_mismatch) -> true;
is_desync_error({payload_size_exceeded, _, _}) -> true;
is_desync_error(_) -> false.

try_connect(#{peers := Peers, blacklist := Blacklist} = S) ->
    Target = target_peers(),
    ReadyCount = length([1 || {_, _, ready} <- Peers]),
    ConnectingCount = length([1 || {_, _, connecting} <- Peers]),
    Need = Target - ReadyCount - ConnectingCount,
    if Need > 0 ->
           case pick_seed(Peers, Blacklist) of
               {ok, {Host, Port}} ->
                   case pequod_peer_sup:start_peer(Host, Port, self()) of
                       {ok, Pid} ->
                           S#{peers => [{Pid, {Host, Port}, connecting} | Peers]};
                       _ -> S
                   end;
               none -> S
           end;
       true -> S
    end.

pick_seed(Peers, Blacklist) ->
    Addrs = [Addr || {_, Addr, _} <- Peers],
    Now = erlang:monotonic_time(second),
    Available = [Seed || Seed <- ?SEEDS_TESTNET4,
        not lists:member(Seed, Addrs),
        not is_blacklisted(Seed, Blacklist, Now)],
    case Available of
        [First | _] -> {ok, First};
        [] -> none
    end.

is_blacklisted({Host, Port}, Blacklist, Now) ->
    case maps:find({Host, Port}, Blacklist) of
        {ok, Until} -> Now < Until;
        error -> false
    end.

terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.
