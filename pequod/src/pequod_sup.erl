%%% @doc Pequod top-level supervisor
-module(pequod_sup).
-behaviour(supervisor).
-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 3, period => 60},
    ChildSpecs = [
        #{id => pequod_db, start => {pequod_db, start_link, []}, restart => permanent},
        #{id => pequod_peer_sup, start => {pequod_peer_sup, start_link, []}, restart => permanent},
        #{id => pequod_peer_manager, start => {pequod_peer_manager, start_link, []}, restart => permanent},
        #{id => pequod_header_sync, start => {pequod_header_sync, start_link, []}, restart => permanent},
        #{id => pequod_block_sync, start => {pequod_block_sync, start_link, []}, restart => permanent}
    ],
    {ok, {SupFlags, ChildSpecs}}.
