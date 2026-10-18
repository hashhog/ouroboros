# RPC

ouroboros answers JSON-RPC over HTTP POST on `127.0.0.1:<--rpc-port>`. Method names, parameters and result shapes follow Bitcoin Core's where the method exists in Core. Authentication is HTTP basic auth with the cookie in `<datadir>/.cookie`, or with `rpcuser` / `rpcpassword` from the config file ([running.md](running.md#config-file)).

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

Wallet methods go to `/wallet/<name>`. With exactly one wallet loaded, `/` also works, as in Core. A JSON array of requests is answered as a batch. Named parameters (`"params": {...}`) are accepted.

## Methods

The list below is what `help` returns: every `rpc_<name>` method of `RPCServer` in `src/ouroboros/rpc.py`, 142 in all. Groups follow Core v31.1's categories. Methods Core lists as hidden are marked ‡.

| Group | Methods |
|---|---|
| Blockchain (36) | `dumptxoutset`, `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockfilter`, `getblockfrompeer`, `getblockhash`, `getblockheader`, `getblockstats`, `getchainstates`, `getchaintips`, `getchaintxstats`, `getdeploymentinfo`, `getdifficulty`, `getmempoolancestors`, `getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`, `gettxout`, `gettxoutproof`, `gettxoutsetinfo`, `gettxspendingprevout`, `importmempool`, `loadtxoutset`, `preciousblock`, `pruneblockchain`, `savemempool`, `scanblocks`, `scantxoutset`, `verifychain`, `verifytxoutproof`, `waitforblock`, `waitforblockheight`, `waitfornewblock` |
| Control (6) | `getmemoryinfo`, `getrpcinfo`, `help`, `logging`, `stop`, `uptime` |
| Mining (7) | `getblocktemplate`, `getmininginfo`, `getnetworkhashps`, `getprioritisedtransactions`, `prioritisetransaction`, `submitblock`, `submitheader` |
| Network (14) | `addnode`, `clearbanned`, `disconnectnode`, `getaddednodeinfo`, `getaddrmaninfo`, `getconnectioncount`, `getnettotals`, `getnetworkinfo`, `getnodeaddresses`, `getpeerinfo`, `listbanned`, `ping`, `setban`, `setnetworkactive` |
| Raw transactions (19) | `analyzepsbt`, `combinepsbt`, `combinerawtransaction`, `converttopsbt`, `createpsbt`, `createrawtransaction`, `decodepsbt`, `decoderawtransaction`, `decodescript`, `descriptorprocesspsbt`, `finalizepsbt`, `fundrawtransaction`, `getrawtransaction`, `joinpsbts`, `sendrawtransaction`, `signrawtransactionwithkey`, `submitpackage`, `testmempoolaccept`, `utxoupdatepsbt` |
| Util (8) | `createmultisig`, `deriveaddresses`, `estimatesmartfee`, `getdescriptorinfo`, `getindexinfo`, `signmessagewithprivkey`, `validateaddress`, `verifymessage` |
| Wallet (34) | `backupwallet`, `bumpfee`, `createwallet`, `encryptwallet`, `getaddressinfo`, `getbalance`, `getbalances`, `getnewaddress`, `getrawchangeaddress`, `gettransaction`, `getwalletinfo`, `importdescriptors`, `keypoolrefill`, `listdescriptors`, `listlockunspent`, `listtransactions`, `listunspent`, `listwalletdir`, `listwallets`, `loadwallet`, `lockunspent`, `psbtbumpfee`, `rescanblockchain`, `restorewallet`, `send`, `sendtoaddress`, `signmessage`, `signrawtransactionwithwallet`, `unloadwallet`, `walletcreatefundedpsbt`, `walletlock`, `walletpassphrase`, `walletpassphrasechange`, `walletprocesspsbt` |
| Hidden in Core (6) | `addpeeraddress`‡, `estimaterawfee`‡, `generatetoaddress`‡, `getorphantxs`‡, `invalidateblock`‡, `reconsiderblock`‡ |

### Not in Core v31.1 (12)

| Method | What it does |
|---|---|
| `dumpmempool` | Same as `savemempool`. |
| `loadmempool` | Loads `mempool.dat`; Core's name for this is `importmempool`, which also exists. |
| `submitblockbatch` | Takes an array of hex blocks and connects them in order; returns `null` or an error string per block. |
| `getsyncstate` | Sync progress in one object (tip, headers, peers). |
| `getcrosscheckstats` | Counters for `OUROBOROS_VALIDATE_CROSS_CHECK=1`, which runs the Rust and Python block validators side by side. |
| `scrubunspendable` | Removes provably unspendable coins (`OP_RETURN`, oversized scripts) left in the UTXO set by older versions. |
| `dumpprivkey`, `importprivkey`, `sethdseed` | Single-key and HD-seed calls from Core's legacy wallet, which Core removed. |
| `dumpmnemonic` | Prints the wallet's BIP-39 mnemonic. |
| `getpayjoinrequest`, `sendpayjoinrequest` | BIP-78 Payjoin sender: build the original PSBT, then post it to a receiver and broadcast the result. |

### In Core v31.1 but not here

`abandontransaction`, `abortrescan`, `createwalletdescriptor`, `generate`, `generateblock`, `generatetodescriptor`, `getaddressesbylabel`, `getdescriptoractivity`, `gethdkeys`, `getmempoolcluster`, `getmempoolfeeratediagram`, `getrawaddrman`, `getreceivedbyaddress`, `getreceivedbylabel`, `importprunedfunds`, `listaddressgroupings`, `listlabels`, `listreceivedbyaddress`, `listreceivedbylabel`, `listsinceblock`, `migratewallet`, `removeprunedfunds`, `sendall`, `sendmany`, `setlabel`, `setmocktime`, `setwalletflag`, `simulaterawtransaction`, `walletdisplayaddress`, the external-signer call `enumeratesigners`, the private-broadcast calls, and the test-only hidden calls (`echo`, `echojson`, `echoipc`, `addconnection`, `mockscheduler`, `sendmsgtopeer`, `syncwithvalidationinterfacequeue`). They return `-32601 Method not found`.

On regtest, use `generatetoaddress` to mine; `generateblock` and `generatetodescriptor` are not implemented.

## Differences from Core

Seen on regtest against Bitcoin Core v31.1, with the same requests sent to both:

| Request | Bitcoin Core | ouroboros |
|---|---|---|
| any successful call, JSON-RPC 1.0 | `{"result":…,"error":null,"id":1}` | `{"jsonrpc":"2.0","result":…,"id":1}` |
| any failing call, JSON-RPC 1.0 | `{"result":null,"error":{…},"id":1}` | `{"jsonrpc":"2.0","error":{…},"id":1}` |
| `help` | Core's grouped help text | One method name per line, all 142, including hidden ones |
| `help getblockcount` | Core's full help text | The method's docstring, here `Return block count` |
| `generateblock` (no arguments) | `-1` with the usage text | `-32601 Method not found` |

Error codes and messages for `decoderawtransaction` on bad hex (`-22 TX decode failed`) and `getblockhash` out of range (`-8 Block height out of range`) match Core, as does `getblockstats` with a stats filter.

Other differences that follow from the code:

- Version 2 PSBTs (BIP-370) are rejected unless `OUROBOROS_PSBT_V2=1` is set; creation calls always produce version 0, as Core does.
- `gettxoutsetinfo` for a past height needs `--coinstatsindex`; without it, a non-tip `hash_or_height` returns `-8`, as in Core.
- `gettxspendingprevout` for confirmed spends needs `--txospenderindex`.

## REST and ZMQ

The code has a REST interface (`src/ouroboros/rest.py`, under `/rest/`) and ZMQ publishers (`hashblock`, `hashtx`, `rawblock`, `rawtx`, `sequence`), but `start` has no option that turns them on and the config file does not reach them ([running.md](running.md#config-file)). With the defaults, `GET /rest/chaininfo.json` returns `{"detail":"Not Found"}`.
