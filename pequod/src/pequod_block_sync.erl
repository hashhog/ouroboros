%%% @doc Block sync: queue heights, assign to peers, validate, store
%%% - Queue of heights to fetch, assign up to max_in_flight (32), max 16 per peer
%%% - On block: validate (hash, prev), store, remove from in-flight
%%% - On timeout: re-queue, record failed peer, assign to different peer
%%% - On peer disconnect: re-queue all in-flight for that peer
%%% Ref: ferrous-utils/sync/src/network/block_sync.rs
-module(pequod_block_sync).
-behaviour(gen_server).
-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(INV_TYPE_BLOCK, 2).
-define(DEFAULT_MAX_IN_FLIGHT, 32).
-define(DEFAULT_IN_FLIGHT_TIMEOUT_SECS, 120).
-define(DEFAULT_BLOCK_RECEIVE_TIMEOUT_SECS, 180).
-define(MAX_PER_PEER, 16).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    pequod_peer_manager:register_block_sink(self()),
    self() ! sync_loop,
    {ok, #{queue => [], in_flight => #{}, peer_count => #{},
           avoid => #{}, pending => false}}.

handle_call(_, _From, S) -> {noreply, S}.
handle_cast(_, S) -> {noreply, S}.

handle_info(sync_loop, S) ->
    S2 = do_sync(S),
    erlang:send_after(2000, self(), sync_loop),
    {noreply, S2};
handle_info({pequod_peer, Pid, <<"block">>, Payload}, S) ->
    S2 = handle_block(Pid, Payload, S),
    {noreply, S2};
handle_info({block_timeout, Hash}, #{in_flight := IF} = S) ->
    case maps:find(Hash, IF) of
        {ok, {Height, Pid, _}} ->
            %% Re-queue, record failed peer for this height (avoid re-assigning to same peer)
            Queue = [Height | maps:get(queue, S, [])],
            Avoid = maps:put(Height, Pid, maps:get(avoid, S, #{})),
            PC = dec_peer_count(maps:get(peer_count, S, #{}), Pid),
            IF2 = maps:remove(Hash, IF),
            {noreply, S#{queue => Queue, in_flight => IF2, avoid => Avoid, peer_count => PC}};
        error -> {noreply, S}
    end;
handle_info({pequod_peer, Pid, closed}, #{in_flight := IF, queue := Q, peer_count := PC} = S) ->
    %% Re-queue all in-flight for this peer
    {Requeue, IF2} = maps:fold(fun(Hash, {Ht, P, _}, {Rq, Acc}) ->
        if P =:= Pid -> {[Ht | Rq], maps:remove(Hash, Acc)};
           true -> {Rq, Acc}
        end
    end, {[], IF}, IF),
    PC2 = maps:remove(Pid, PC),
    {noreply, S#{queue => Requeue ++ Q, in_flight => IF2, peer_count => PC2}};
handle_info({pequod_peer, _Pid, closed}, S) ->
    {noreply, S};
handle_info(_, S) -> {noreply, S}.

terminate(_, _) ->
    pequod_peer_manager:unregister_block_sink(),
    ok.
code_change(_, S, _) -> {ok, S}.

do_sync(S) ->
    {Queue, IF, PC} = ensure_queue(S),
    MaxIF = get_env(max_in_flight, ?DEFAULT_MAX_IN_FLIGHT),
    ToAssign = min(MaxIF - maps:size(IF), length(Queue)),
    if ToAssign > 0, Queue =/= [] ->
           {ToFetch, Rest} = lists:split(ToAssign, Queue),
           S2 = assign_blocks(ToFetch, S#{queue => Rest, in_flight => IF, peer_count => PC}),
           S2;
       true -> S#{queue => Queue, in_flight => IF, peer_count => PC}
    end.

ensure_queue(#{queue := Q, in_flight := IF, peer_count := PC}) when Q =/= [] ->
    {Q, IF, PC};
ensure_queue(#{in_flight := IF, peer_count := PC}) ->
    {_, BestH} = pequod_db:get_best_block(),
    Q = if BestH < 0 -> [];
           true -> [H || H <- lists:seq(0, BestH), not block_fetched(H)]
       end,
    {Q, IF, PC}.

block_fetched(Height) ->
    case pequod_db:get_block_hash_by_height(Height) of
        {ok, Hash} -> case pequod_db:get_block(Hash) of {ok, _} -> true; _ -> false end;
        _ -> false
    end.

assign_blocks([], S) -> S;
assign_blocks([H | Heights], #{in_flight := IF, peer_count := PC, avoid := Avoid} = S) ->
    Peers = pequod_peer_manager:drain_peers(),
    AvoidPid = maps:get(H, Avoid, undefined),
    Available = [{Pid, _Addr} || {_Addr, Pid} <- Peers,
        AvoidPid =/= Pid,
        maps:get(Pid, PC, 0) < ?MAX_PER_PEER],
    case Available of
        [] -> S#{queue => [H | Heights]};
        [{Pid, _} | _] ->
            {ok, Hash} = pequod_db:get_block_hash_by_height(H),
            Payload = pequod_getdata:encode([{?INV_TYPE_BLOCK, Hash}]),
            Magic = pequod_chain_params:get_magic(application:get_env(pequod, network, testnet4)),
            Msg = pequod_protocol:encode_header(Magic, <<"getdata">>, Payload),
            ok = pequod_peer:send_message(Pid, <<Msg/binary, Payload/binary>>),
            TimeoutSecs = get_env(block_receive_timeout_secs, ?DEFAULT_BLOCK_RECEIVE_TIMEOUT_SECS),
            erlang:send_after(TimeoutSecs * 1000, self(), {block_timeout, Hash}),
            S2 = S#{in_flight => maps:put(Hash, {H, Pid, erlang:monotonic_time(millisecond)}, IF),
                  peer_count => inc_peer_count(PC, Pid),
                  avoid => maps:remove(H, Avoid)},
            assign_blocks(Heights, S2)
    end.

inc_peer_count(PC, Pid) -> maps:put(Pid, maps:get(Pid, PC, 0) + 1, PC).
dec_peer_count(PC, Pid) ->
    N = maps:get(Pid, PC, 1) - 1,
    if N =< 0 -> maps:remove(Pid, PC);
       true -> maps:put(Pid, N, PC)
    end.

handle_block(Pid, Payload, #{in_flight := IF} = S) ->
    case pequod_block:parse(Payload) of
        {ok, #{header := Header, full := Full}} ->
            Hash = pequod_block:header_hash(Header),
            case maps:find(Hash, IF) of
                {ok, {Height, Pid, _}} ->
                    PrevHash = pequod_block:header_prev_hash(Header),
                    PrevOk = case Height of
                        0 -> PrevHash =:= <<0:256>>;  %% Genesis prev_blockhash is 32 zero bytes
                        _ -> case pequod_db:get_block_hash_by_height(Height - 1) of
                            {ok, PrevHash} -> true;
                            _ -> false
                        end
                    end,
                    if PrevOk ->
                            pequod_db:put_block(Hash, Full),
                            pequod_db:put_block_index(Height, Hash),
                            IF2 = maps:remove(Hash, IF),
                            PC = dec_peer_count(maps:get(peer_count, S, #{}), Pid),
                            S#{in_flight => IF2, peer_count => PC};
                       true -> S
                    end;
                _ -> S
            end;
        _ -> S
    end.

get_env(Key, Default) ->
    AppKey = case Key of
        max_in_flight -> max_in_flight;
        in_flight_timeout_secs -> in_flight_timeout_secs;
        block_receive_timeout_secs -> block_receive_timeout_secs
    end,
    case application:get_env(pequod, AppKey) of
        {ok, N} when is_integer(N) -> N;
        _ ->
            Var = case Key of
                max_in_flight -> "PEQUOD_MAX_IN_FLIGHT";
                in_flight_timeout_secs -> "PEQUOD_IN_FLIGHT_TIMEOUT_SECS";
                block_receive_timeout_secs -> "PEQUOD_BLOCK_RECEIVE_TIMEOUT_SECS"
            end,
            case os:getenv(Var) of
                false -> Default;
                V -> case string:to_integer(V) of {N, _} when is_integer(N) -> N; _ -> Default end
            end
    end.
