%%% @doc Pequod application - Bitcoin P2P full node in Erlang
-module(pequod_app).
-behaviour(application).
-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    pequod_sup:start_link().

stop(_State) ->
    ok.
