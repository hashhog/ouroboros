%%% @doc Dynamic supervisor for peer workers
-module(pequod_peer_sup).
-behaviour(supervisor).
-export([start_link/0, start_peer/3]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_peer(Host, Port, Parent) ->
    supervisor:start_child(?MODULE, [Host, Port, Parent]).

init([]) ->
    SupFlags = #{strategy => simple_one_for_one, intensity => 10, period => 60},
    ChildSpec = #{id => pequod_peer, start => {pequod_peer, start_link, []},
                  restart => temporary},
    {ok, {SupFlags, [ChildSpec]}}.
