%%% @doc Header sync coordinator: getheaders/headers, PoW validation, storage
%%% 1. gen_server: get peer from pequod_peer_manager, send getheaders with locator [genesis_hash], hash_stop=0
%%% 2. On headers: validate each (PoW, prev_hash chain, timestamp), store in pequod_db
%%% 3. If count=2000: locator = last few hashes, getheaders again
%%% 4. PoW: hash <= target from bits, little-endian comparison (ref: ferrous-utils/sync/src/validate/pow.rs)
%%% Ref: ferrous-utils/sync/src/network/header_sync.rs
-module(pequod_header_sync).
-behaviour(gen_server).
-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(BATCH_SIZE, 2000).
-define(MAX_FUTURE_SECONDS, 7200).  %% 2 hours - reject headers too far in future

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    self() ! sync_loop,
    {ok, #{peer => undefined, pending => false}}.

handle_call(_, _From, S) -> {noreply, S}.
handle_cast(_, S) -> {noreply, S}.

handle_info(sync_loop, S) ->
    S2 = do_sync(S),
    {noreply, S2};
handle_info({pequod_peer, _Pid, <<"headers">>, Payload}, #{pending := true, peer := Pid} = S) ->
    S2 = handle_headers(Pid, Payload, S),
    {noreply, S2};
handle_info({pequod_peer, _Pid, _Cmd, _Payload}, S) ->
    {noreply, S};
handle_info(_, S) -> {noreply, S}.

terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.

do_sync(#{peer := undefined} = S) ->
    case pequod_peer_manager:request_peer(self()) of
        {ok, Pid} ->
            pequod_peer_manager:forward_to(Pid, self()),
            request_headers(Pid, S#{peer => Pid});
        {error, no_peers} ->
            erlang:send_after(2000, self(), sync_loop),
            S
    end;
do_sync(S) -> S.

request_headers(Pid, S) ->
    Network = application:get_env(pequod, network, testnet4),
    GenesisHash = pequod_chain_params:genesis_hash(Network),
    Magic = pequod_chain_params:get_magic(Network),
    Payload = pequod_getheaders:encode(70015, [GenesisHash], <<0:256>>),
    Msg = pequod_protocol:encode_header(Magic, <<"getheaders">>, Payload),
    ok = pequod_peer:send_message(Pid, <<Msg/binary, Payload/binary>>),
    S#{pending => true}.

handle_headers(Pid, Payload, S) ->
    case pequod_headers:parse(Payload) of
        {ok, HeaderList} ->
            Network = application:get_env(pequod, network, testnet4),
            GenesisHash = pequod_chain_params:genesis_hash(Network),
            {_, BestHeight} = pequod_db:get_best_block(),
            StartHeight = case BestHeight of -1 -> 1; N -> N + 1 end,
            case validate_and_store(HeaderList, StartHeight, GenesisHash, Network) of
                ok ->
                    Count = length(HeaderList),
                    if Count < ?BATCH_SIZE ->
                           pequod_peer_manager:release_peer(Pid, self()),
                           erlang:send_after(60000, self(), sync_loop),
                           S#{peer => undefined, pending => false};
                       true ->
                           %% Locator = last few hashes (per spec: "locator = last few hashes")
                           LastFew = last_n_hashes(HeaderList, 3),
                           Payload2 = pequod_getheaders:encode(70015, LastFew, <<0:256>>),
                           Magic = pequod_chain_params:get_magic(Network),
                           Msg = pequod_protocol:encode_header(Magic, <<"getheaders">>, Payload2),
                           ok = pequod_peer:send_message(Pid, <<Msg/binary, Payload2/binary>>),
                           S
                    end;
                {error, _} ->
                    pequod_peer_manager:release_peer(Pid, self()),
                    erlang:send_after(5000, self(), sync_loop),
                    S#{peer => undefined, pending => false}
            end;
        {error, _} ->
            S#{pending => false}
    end.

validate_and_store([], _StartHeight, _GenesisHash, _Network) -> ok;
validate_and_store(HeaderList, StartHeight, GenesisHash, Network) ->
    try
        {PrevHash, H} = case StartHeight of
            1 ->
                [First | Rest] = HeaderList,
                Prev = header_prev_hash(First),
                if Prev =/= GenesisHash -> throw({invalid_chain, genesis});
                   true -> ok
                end,
                case validate_timestamp(First) of ok -> ok; {error, _} -> throw(invalid_timestamp) end,
                <<_:72/binary, Bits:32/little, _/binary>> = First,
                Target = pequod_pow:bits_to_target(Bits),
                case pequod_pow:validate_pow(First, Target) of false -> throw(invalid_pow); _ -> ok end,
                store_header(First, 1),
                {hash_header(First), Rest};
            _ ->
                case pequod_db:get_block_hash_by_height(StartHeight - 1) of
                    {ok, PrevHash0} -> {PrevHash0, HeaderList};
                    {error, _} -> throw(prev_block_not_found)
                end
        end,
        store_chain(H, StartHeight, PrevHash, Network)
    catch throw:E -> {error, E}
    end.

store_chain([], _H, _Prev, _Network) -> ok;
store_chain([Header | Rest], Height, PrevHash, _Network) ->
    case header_prev_hash(Header) of
        PrevHash -> ok;
        _ -> throw({invalid_chain, prev_hash})
    end,
    case validate_timestamp(Header) of
        ok -> ok;
        {error, _} -> throw(invalid_timestamp)
    end,
    <<_:72/binary, Bits:32/little, _/binary>> = Header,
    Target = pequod_pow:bits_to_target(Bits),
    case pequod_pow:validate_pow(Header, Target) of
        true -> ok;
        false -> throw({invalid_pow, Height})
    end,
    store_header(Header, Height),
    Hash = hash_header(Header),
    store_chain(Rest, Height + 1, Hash, _Network).

store_header(Header80, Height) ->
    Hash = hash_header(Header80),
    pequod_db:put_block(Hash, Header80),
    pequod_db:put_block_index(Height, Hash),
    pequod_db:set_best_block(Hash, Height).

hash_header(<<Header:80/binary>>) ->
    crypto:hash(sha256, crypto:hash(sha256, Header)).

%% Last N hashes from header list (newest first, for getheaders locator)
last_n_hashes(HeaderList, N) ->
    Rev = lists:reverse(HeaderList),
    [hash_header(H) || H <- lists:sublist(Rev, N)].

%% Validate timestamp: not more than 2 hours in future (ref: header.rs validate_timestamp)
validate_timestamp(<<_:68/binary, Time:32/little, _/binary>>) ->
    Now = erlang:system_time(second),
    if Time =< Now + ?MAX_FUTURE_SECONDS -> ok;
       true -> {error, too_far_in_future}
    end.

%% 80-byte header: version(4) + prev_blockhash(32) + merkle_root(32) + time(4) + bits(4) + nonce(4)
header_prev_hash(<<_:4/binary, PrevHash:32/binary, _/binary>>) -> PrevHash.

