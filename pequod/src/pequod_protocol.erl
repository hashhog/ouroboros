%%% @doc Bitcoin P2P message protocol - 24-byte header encode/decode
%%% Reference: bitcoin/src/protocol.h CMessageHeader, ferrous-utils/sync/src/network/messages.rs
-module(pequod_protocol).
-export([encode_header/3, decode_header/1, checksum/1, command_to_bytes/1, bytes_to_command/1]).

-define(HEADER_SIZE, 24).
-define(COMMAND_SIZE, 12).
%% 4MB payload sanity - if Size > 4MB treat as desync (Bitcoin P2P spec)
-define(SANITY_MAX_PAYLOAD, 4 * 1024 * 1024).

%% @doc Encode 24-byte message header.
%% Magic(4) + Command(12 null-pad) + Size(4 LE) + Checksum(4 LE)
-spec encode_header(binary(), string() | binary(), binary()) -> binary().
encode_header(Magic, Command, Payload) when is_list(Command) ->
    encode_header(Magic, list_to_binary(Command), Payload);
encode_header(Magic, Command, Payload) ->
    Size = byte_size(Payload),
    Checksum = checksum(Payload),
    CommandPadded = pad_command(Command, ?COMMAND_SIZE),
    <<Magic:4/binary, CommandPadded:12/binary, Size:32/little, Checksum:4/binary>>.

%% @doc Decode 24-byte header. Returns {ok, Magic, Command, Size, Checksum} or {error, Reason}
-spec decode_header(binary()) -> {ok, binary(), binary(), non_neg_integer(), binary()} | {error, term()}.
decode_header(<<Magic:4/binary, Command:12/binary, Size:32/little, Checksum:4/binary>>)
  when byte_size(Magic) =:= 4 ->
    case Size of
        S when S > ?SANITY_MAX_PAYLOAD ->
            {error, {payload_size_exceeded, S, ?SANITY_MAX_PAYLOAD}};
        S when S > 32 * 1024 * 1024 ->
            {error, {payload_too_large, S}};
        _ ->
            CommandTrimmed = trim_null_padding(Command),
            {ok, Magic, CommandTrimmed, Size, Checksum}
    end;
decode_header(Bin) when byte_size(Bin) < ?HEADER_SIZE ->
    {error, {header_too_short, byte_size(Bin)}};
decode_header(_) ->
    {error, invalid_header}.

%% @doc Checksum = first 4 bytes of SHA256(SHA256(Payload))
-spec checksum(binary()) -> binary().
checksum(Payload) ->
    Hash = crypto:hash(sha256, crypto:hash(sha256, Payload)),
    <<Checksum:4/binary, _/binary>> = Hash,
    Checksum.

%% @doc Convert command string to 12-byte null-padded binary
-spec command_to_bytes(string() | binary()) -> binary().
command_to_bytes(Command) when is_list(Command) ->
    command_to_bytes(list_to_binary(Command));
command_to_bytes(Command) when is_binary(Command) ->
    pad_command(Command, ?COMMAND_SIZE).

pad_command(Command, Len) when byte_size(Command) >= Len ->
    binary:part(Command, 0, Len);
pad_command(Command, Len) ->
    Padding = Len - byte_size(Command),
    <<Command/binary, (binary:copy(<<0>>, Padding))/binary>>.

trim_null_padding(Bin) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} -> binary:part(Bin, 0, Pos);
        nomatch  -> Bin
    end.

bytes_to_command(Bin) ->
    trim_null_padding(Bin).
