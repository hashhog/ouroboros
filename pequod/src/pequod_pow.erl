%%% @doc Proof-of-Work validation - little-endian hash comparison
%%% Ref: ferrous-utils/sync/src/validate/pow.rs - from_little_endian for hash
-module(pequod_pow).
-export([bits_to_target/1, validate_pow/2]).

%%% Bits format: exponent (high 8 bits) + mantissa (low 24 bits)
%%% target = mantissa * 256^(exponent - 3)
-spec bits_to_target(non_neg_integer()) -> non_neg_integer().
bits_to_target(Bits) when is_integer(Bits) ->
    Exponent = Bits bsr 24,
    Mantissa = Bits band 16#007fffff,
    if Exponent =< 3 ->
           Mantissa bsr (8 * (3 - Exponent));
       true ->
           Mantissa bsl (8 * (Exponent - 3))
    end.

%%% Validate: double-SHA256(header) as LE integer must be =< target
%%% Hash is Bitcoin internal format (little-endian) - interpret as LE integer
-spec validate_pow(binary(), non_neg_integer()) -> boolean().
validate_pow(Header80, Target) when byte_size(Header80) =:= 80, is_integer(Target) ->
    Hash = crypto:hash(sha256, crypto:hash(sha256, Header80)),
    HashInt = binary_to_le_int(Hash),
    HashInt =< Target.

binary_to_le_int(<<>>) -> 0;
binary_to_le_int(<<B, Rest/binary>>) ->
    B + (binary_to_le_int(Rest) bsl 8).
