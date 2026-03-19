%%% @doc ETS storage: blocks, block_index, meta
%%% API: put_block/2, get_block/1, get_block_hash_by_height/1, get_best_block/0, set_best_block/2
-module(pequod_db).
-behaviour(gen_server).
-export([start_link/0, put_block/2, put_block_index/2, get_block/1, get_block_hash_by_height/1, get_best_block/0, set_best_block/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

put_block(Hash, Block) when is_binary(Hash), is_binary(Block) ->
    gen_server:call(?MODULE, {put_block, Hash, Block}).

put_block_index(Height, Hash) when is_integer(Height), is_binary(Hash) ->
    gen_server:call(?MODULE, {put_block_index, Height, Hash}).

get_block(Hash) when is_binary(Hash) ->
    gen_server:call(?MODULE, {get_block, Hash}).

get_block_hash_by_height(Height) when is_integer(Height), Height >= 0 ->
    gen_server:call(?MODULE, {get_block_hash_by_height, Height}).

get_best_block() ->
    gen_server:call(?MODULE, get_best_block).

set_best_block(Hash, Height) when is_binary(Hash), is_integer(Height) ->
    gen_server:call(?MODULE, {set_best_block, Hash, Height}).

init([]) ->
    Blocks = ets:new(pequod_blocks, [set, public, named_table]),
    BlockIndex = ets:new(pequod_block_index, [set, public, named_table]),
    Meta = ets:new(pequod_meta, [set, public, named_table]),
    ets:insert(Meta, {best_hash, <<>>}),
    ets:insert(Meta, {best_height, -1}),
    %% Genesis at height 0 for block sync (header_sync starts from block 1)
    GenesisHash = pequod_chain_params:genesis_hash(application:get_env(pequod, network, testnet4)),
    ets:insert(BlockIndex, {0, GenesisHash}),
    {ok, #{blocks => Blocks, block_index => BlockIndex, meta => Meta}}.

handle_call({put_block, Hash, Block}, _From, S) ->
    ets:insert(pequod_blocks, {Hash, Block}),
    {reply, ok, S};
handle_call({put_block_index, Height, Hash}, _From, S) ->
    ets:insert(pequod_block_index, {Height, Hash}),
    {reply, ok, S};
handle_call({get_block, Hash}, _From, S) ->
    R = case ets:lookup(pequod_blocks, Hash) of
        [{Hash, Block}] -> {ok, Block};
        [] -> {error, not_found}
    end,
    {reply, R, S};
handle_call({get_block_hash_by_height, Height}, _From, S) ->
    R = case ets:lookup(pequod_block_index, Height) of
        [{Height, Hash}] -> {ok, Hash};
        [] -> {error, not_found}
    end,
    {reply, R, S};
handle_call(get_best_block, _From, S) ->
    [{best_hash, H}] = ets:lookup(pequod_meta, best_hash),
    [{best_height, N}] = ets:lookup(pequod_meta, best_height),
    {reply, {H, N}, S};
handle_call({set_best_block, Hash, Height}, _From, S) ->
    ets:insert(pequod_meta, {best_hash, Hash}),
    ets:insert(pequod_meta, {best_height, Height}),
    {reply, ok, S};
handle_call(_, _From, S) -> {reply, {error, unknown}, S}.

handle_cast(_, S) -> {noreply, S}.
handle_info(_, S) -> {noreply, S}.
terminate(_, _) -> ok.
code_change(_, S, _) -> {ok, S}.
