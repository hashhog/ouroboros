"""Command-line interface for the Bitcoin node."""

import asyncio
import os
import shutil
import signal
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)
from rich.table import Table

from ouroboros.daemon import (
    PidFile,
    daemonize,
    install_sighup_log_reopen,
    parse_debug_categories,
    sd_notify_ready,
    sd_notify_status,
    sd_notify_stopping,
)
from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool
from ouroboros.node import BitcoinNode
from ouroboros.sync_manager import SyncManager, SyncProgress

console = Console()

# Global variables for signal handling
_sync_manager: SyncManager | None = None
_node: BitcoinNode | None = None
_cancelled = False
_interruption_shown = False
_pid_file: PidFile | None = None


def handle_sigint(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully.

    Sets _cancelled and requests sync/node stop. Does NOT call sys.exit() here -
    the main sync loop will see the flag and exit cleanly. Calling sys.exit() from
    a signal handler while threads are running causes segfaults (Rust/PyO3 tear-down).
    """
    global _cancelled, _sync_manager, _node, _interruption_shown
    _cancelled = True

    if not _interruption_shown:
        _interruption_shown = True
        console.print("\n[yellow]Interruption received. Shutting down gracefully...[/yellow]")

    if _sync_manager is not None:
        try:
            _sync_manager.cancel_sync()
        except Exception as e:
            console.print(f"[red]Error cancelling sync: {e}[/red]")

    if _node is not None:
        try:
            asyncio.run(_node.stop())
        except Exception as e:
            console.print(f"[red]Error stopping node: {e}[/red]")

    # Best-effort PID file cleanup + systemd STOPPING=1.
    if _pid_file is not None:
        try:
            _pid_file.remove()
        except Exception:
            pass
    try:
        sd_notify_stopping("ouroboros stopping")
    except Exception:
        pass


def handle_sigterm(signum, frame):
    """Handle SIGTERM gracefully."""
    handle_sigint(signum, frame)


# Register signal handlers
signal.signal(signal.SIGINT, handle_sigint)
signal.signal(signal.SIGTERM, handle_sigterm)


def expand_path(path_str: str) -> Path:
    """Expand user home directory in path."""
    return Path(path_str).expanduser()


@click.group()
@click.option(
    "--data-dir",
    default="~/.ouroboros",
    help="Data directory (overridden by OROBOROS_DATADIR env)",
    callback=lambda ctx, param, value: str(expand_path(value)),
)
@click.option(
    "--config",
    "config_file",
    default=None,
    help="Path to ouroboros.conf (default: data_dir/ouroboros.conf)",
)
@click.option(
    "--network",
    default="mainnet",
    type=click.Choice(["mainnet", "testnet", "testnet3", "testnet4", "regtest", "signet"]),
    help="Bitcoin network",
)
@click.option(
    "--debug",
    default=None,
    is_flag=False,
    flag_value="all",
    help=(
        "Enable debug logging. Pass without an argument for all categories, "
        "or a comma-separated list (Bitcoin Core parity): "
        "--debug=net,mempool,validation. '0' disables, '1'/'all' enables every "
        "category."
    ),
)
@click.option("--log-json", is_flag=True, help="Emit structured JSON log lines")
@click.option(
    "--printtoconsole/--noprinttoconsole",
    "print_to_console",
    default=None,
    help=(
        "Send log output to stderr (in addition to the rotating log file). "
        "Default: on when running in the foreground, off under --daemon."
    ),
)
@click.pass_context
def cli(ctx, data_dir, config_file, network, debug, log_json, print_to_console):
    """Bitcoin Hybrid Node - Rust sync, Python operations"""
    from ouroboros.logging_config import configure_logging

    # OROBOROS_DATADIR overrides --data-dir
    if os.environ.get("OUROBOROS_DATADIR"):
        data_dir = str(expand_path(os.environ["OUROBOROS_DATADIR"]))
    # Ensure data directory exists
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    # --debug accepts a category list (Core parity).  ``--debug`` without
    # an argument falls through as ``"all"``; absent flag is None.
    debug_categories = parse_debug_categories(debug)
    debug_enabled = debug is not None and debug not in {"0", "false", "no"}

    if debug_enabled:
        os.environ["OUROBOROS_VERBOSE"] = "1"

    # Default: stderr on, rotating file on.  Operators can opt out with
    # --noprinttoconsole; subcommands (notably ``start --daemon``) flip
    # the default to file-only.
    effective_console = True if print_to_console is None else bool(print_to_console)

    configure_logging(
        debug=debug_enabled,
        json_format=log_json,
        log_file=str(Path(data_dir) / "ouroboros.log"),
        debug_categories=debug_categories,
        print_to_console=effective_console,
    )

    # Wire SIGHUP -> reopen rotating log file (parity with Core, lets
    # logrotate rotate without restarting).
    from ouroboros.logging_config import reopen_log_file
    install_sighup_log_reopen(reopen_log_file)

    # Config path: --config or data_dir/ouroboros.conf
    config_path = config_file or str(Path(data_dir) / "ouroboros.conf")
    ctx.obj = {
        "data_dir": data_dir,
        "network": network,
        "config_path": config_path,
        "debug": debug_enabled,
        "debug_categories": debug_categories,
        "log_json": log_json,
        "print_to_console_explicit": print_to_console,
    }


@cli.command()
@click.option(
    "--reset",
    is_flag=True,
    help="Clear chainstate before syncing. Use when you see 'Headers don't connect' or after switching networks.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    metavar="N",
    help="Sync only the first N blocks (useful for quick validation).",
)
@click.pass_context
def sync(ctx, reset, limit):
    """Synchronize blockchain (initial download)"""
    global _sync_manager, _cancelled, _interruption_shown
    _cancelled = False
    _interruption_shown = False

    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]

    if reset:
        data_path = Path(data_dir)
        if data_path.exists():
            config_file = data_path / "ouroboros.conf"
            for item in list(data_path.iterdir()):
                if item != config_file:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
            console.print("[yellow]Chainstate cleared.[/yellow]")
        else:
            data_path.mkdir(parents=True, exist_ok=True)

    limit_info = f" (limit: {limit} blocks)" if limit else ""
    console.print(
        f"[bold]ouroboros sync[/bold] — [cyan]{network}[/cyan]{limit_info}\n"
        f"[dim]Data: {data_dir}[/dim]"
    )

    # Create SyncManager
    try:
        _sync_manager = SyncManager(data_dir, network)
    except Exception as e:
        console.print(f"[red]Error initializing sync manager: {e}[/red]")
        sys.exit(1)

    # Check if already synced
    if _sync_manager.is_synced():
        console.print("[green]✓ Already synced[/green]")
        return

    # Progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.fields[info]}"),
        console=console,
        redirect_stderr=True,
    ) as progress:
        task = progress.add_task(
            "[cyan]Connecting...[/cyan]",
            total=100.0,
            info="",
        )

        _last_phase: str | None = None
        _total_blocks_downloaded = 0

        def format_eta(seconds: int) -> str:
            if seconds >= 999 * 3600:
                return ""
            if seconds < 60:
                return f"{seconds}s"
            if seconds < 3600:
                return f"{seconds // 60}m {seconds % 60}s"
            return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

        def progress_callback(prog: SyncProgress):
            nonlocal _last_phase, _total_blocks_downloaded
            global _cancelled
            if _cancelled:
                return

            if prog.phase == "block" and _last_phase == "header":
                progress.update(task, completed=0)
            _last_phase = prog.phase
            _total_blocks_downloaded = prog.current_height

            peers_str = f"[dim]{prog.peer_count} peers[/dim]" if prog.peer_count > 0 else ""

            if prog.phase == "header":
                if not prog.total_known:
                    desc = "[cyan]Headers[/cyan]"
                    info = f"[dim]connecting...[/dim]  {peers_str}"
                else:
                    desc = "[cyan]Headers[/cyan]"
                    info = f"[cyan]{prog.current_height:,}[/cyan] / {prog.total_height:,}  {peers_str}"
            else:
                eta = format_eta(prog.eta_seconds)
                eta_str = f"  [dim]ETA {eta}[/dim]" if eta else ""
                desc = "[cyan]Blocks[/cyan]"
                info = (
                    f"[cyan]{prog.current_height:,}[/cyan] / {prog.total_height:,}"
                    f"  [yellow]{prog.blocks_per_second:.1f} blk/s[/yellow]"
                    f"{eta_str}  {peers_str}"
                )

            progress.update(
                task,
                completed=prog.progress_percent,
                description=desc,
                info=info,
            )

        def cancel_check() -> bool:
            return _cancelled

        def format_duration(secs: float) -> str:
            if secs < 60:
                return f"{secs:.1f}s"
            if secs < 3600:
                return f"{int(secs // 60)}m {int(secs % 60)}s"
            h = int(secs // 3600)
            m = int((secs % 3600) // 60)
            return f"{h}h {m}m"

        # Start sync
        sync_start_time = time.time()
        try:
            success = _sync_manager.perform_initial_sync(
                progress_callback=progress_callback,
                cancel_check=cancel_check,
                progress_interval=1.0,
                limit=limit,
            )

            if success:
                progress.update(task, completed=100.0)
                duration_secs = time.time() - sync_start_time
                final_progress = _sync_manager.get_progress() or _sync_manager.last_progress
                final_height = final_progress.current_height if final_progress else 0
                avg_speed = final_height / duration_secs if duration_secs > 0 else 0
                console.print(
                    f"\n[green]✓ Synced to {final_height:,}[/green]"
                    f" in [cyan]{format_duration(duration_secs)}[/cyan]"
                    f" [dim](avg {avg_speed:.1f} blk/s)[/dim]"
                )
            elif _cancelled:
                duration_secs = time.time() - sync_start_time
                console.print(
                    f"\n[yellow]Sync cancelled at height {_total_blocks_downloaded:,}[/yellow]"
                    f" after [cyan]{format_duration(duration_secs)}[/cyan]"
                )
            else:
                error = _sync_manager.last_error
                console.print(f"\n[red]✗ Sync failed: {error}[/red]")
                sys.exit(1)

        except KeyboardInterrupt:
            _cancelled = True
            _sync_manager.cancel_sync()
            console.print("\n[yellow]Sync interrupted[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]✗ Sync error: {e}[/red]")
            sys.exit(1)


@cli.command()
@click.option("--rpc-port", default=8332, type=int, help="RPC server port")
@click.option("--p2p-port", default=8333, type=int, help="P2P network port")
@click.option("--listen/--nolisten", default=True, help="Accept inbound P2P connections")
@click.option("--connect", multiple=True, help="Connect to ONLY these peer(s) host:port (repeatable). Implies -nodnsseed and disables addrman/auto-outbound dialing (Bitcoin Core -connect semantics).")
@click.option(
    "--dnsseed/--nodnsseed",
    default=None,
    help=(
        "Query DNS seeds to bootstrap peers (default: from config; config "
        "default is on). --nodnsseed suppresses DNS seeding only. --connect "
        "forces this off regardless (Core -connect implies -dnsseed=0)."
    ),
)
@click.option("--force", is_flag=True, default=False, help="Skip sync check prompt")
@click.option(
    "--v2transport/--nov2transport",
    default=None,
    help=(
        "Enable BIP 324 v2 encrypted P2P transport (default: from config; "
        "config default is on). v1 fall-back is automatic per address."
    ),
)
@click.option(
    "--peerbloomfilters/--nopeerbloomfilters",
    default=None,
    help=(
        "Advertise NODE_BLOOM (BIP 111) and service BIP-35 MEMPOOL "
        "requests (default: from config; config default is off, matching "
        "Bitcoin Core's DEFAULT_PEERBLOOMFILTERS=false)."
    ),
)
@click.option(
    "--blockfilterindex/--noblockfilterindex",
    default=None,
    help=(
        "Maintain a BIP 157/158 basic block filter index, serve cfilter / "
        "cfheaders / cfcheckpt P2P queries, and advertise "
        "NODE_COMPACT_FILTERS (default: from config; config default is "
        "off, matching Bitcoin Core's -blockfilterindex=0)."
    ),
)
@click.option(
    "--cfilter",
    "cfilter",
    type=int,
    default=None,
    help=(
        "Compact-block-filter index mode (BIP 157/158).  ``0`` = off, "
        "``1`` = basic filter index (equivalent to "
        "--blockfilterindex).  Convenience alias for the boolean "
        "--blockfilterindex flag."
    ),
)
@click.option(
    "--coinstatsindex/--nocoinstatsindex",
    default=None,
    help=(
        "Maintain a coin-stats index: a per-height running MuHash3072 "
        "commitment over the UTXO set (plus counts / total amount) so "
        "gettxoutsetinfo can answer for a historical hash_or_height and "
        "getindexinfo reports it (default: from config; config default is "
        "off, matching Bitcoin Core's -coinstatsindex=0)."
    ),
)
@click.option(
    "--txospenderindex/--notxospenderindex",
    default=None,
    help=(
        "Maintain a transaction-output spender index: for every non-coinbase "
        "input of every connected block, map the spent outpoint to its "
        "spending tx so gettxspendingprevout can resolve confirmed spends "
        "(options.mempool_only=false) and getindexinfo reports it (default: "
        "from config; config default is off, matching Bitcoin Core's "
        "-txospenderindex=0)."
    ),
)
@click.option(
    "--daemon",
    is_flag=True,
    default=False,
    help=(
        "Detach from the controlling terminal after init (POSIX double-fork, "
        "parity with Bitcoin Core's -daemon). Stdio is redirected to /dev/null "
        "and console logging is disabled unless --printtoconsole is explicit."
    ),
)
@click.option(
    "--pid",
    "pid_path",
    default=None,
    help=(
        "Path for the PID file (default: <datadir>/ouroboros.pid). Written "
        "at startup, removed on graceful shutdown."
    ),
)
@click.option(
    "--reindex",
    is_flag=True,
    default=False,
    help=(
        "Marker flag accepted for Bitcoin Core operational parity. Honest "
        "progress: full block-storage reindex is not yet implemented; the "
        "flag is recognised so ops scripts won't error, and a clear warning "
        "is emitted at startup. Use --reset on `ouroboros sync` to clear "
        "chainstate and re-run IBD."
    ),
)
@click.option(
    "--rpc-tls-cert",
    "rpc_tls_cert",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Path to a PEM-encoded TLS certificate (chain). When set together "
        "with --rpc-tls-key the RPC server terminates HTTPS via uvicorn's "
        "ssl_certfile/ssl_keyfile. Both-or-neither: passing only one is a "
        "startup error. When neither is set the server listens over plain "
        "HTTP (existing behaviour). Mirrors Bitcoin Core's "
        "-rpcsslcertificatechainfile."
    ),
)
@click.option(
    "--rpc-tls-key",
    "rpc_tls_key",
    type=click.Path(dir_okay=False),
    default=None,
    help=(
        "Path to the PEM-encoded TLS private key matching --rpc-tls-cert. "
        "See --rpc-tls-cert for usage; the two flags must be set together."
    ),
)
@click.pass_context
def start(
    ctx, rpc_port, p2p_port, listen, connect, dnsseed, force, v2transport,
    peerbloomfilters, blockfilterindex, cfilter, coinstatsindex,
    txospenderindex, daemon,
    pid_path, reindex, rpc_tls_cert, rpc_tls_key,
):
    """Start the Bitcoin node"""
    global _node, _cancelled, _pid_file
    _cancelled = False

    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]

    if reindex:
        # Honest-progress marker.  See --reindex help text and CLAUDE.md
        # ops-parity audit: full reindex is deferred — operators wanting
        # to clear and rebuild can use ``ouroboros sync --reset``.
        console.print(
            "[yellow]⚠ --reindex acknowledged but not implemented; full block "
            "reindex is deferred. Use 'ouroboros sync --reset' to clear "
            "chainstate and re-IBD.[/yellow]"
        )
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "--reindex requested but not implemented; continuing as a normal "
            "startup. Use 'ouroboros sync --reset' to rebuild from scratch."
        )

    console.print(Panel.fit(
        f"[bold]Starting Bitcoin Node[/bold]\n"
        f"Network: [cyan]{network}[/cyan]\n"
        f"Data directory: [cyan]{data_dir}[/cyan]\n"
        f"RPC port: [cyan]{rpc_port}[/cyan] | P2P port: [cyan]{p2p_port}[/cyan]"
        + (f"\nMode: [cyan]daemon[/cyan]" if daemon else "")
        + f"\n\n[dim]Node will display status when ready. Press Ctrl+C to stop.[/dim]",
        border_style="green"
    ))

    # Check if synced (release SyncManager before node opens DB to avoid RocksDB lock conflict)
    # Auto-skip interactive prompt when --force is set, stdin is not a TTY,
    # or network is not mainnet (testnet/regtest users always want to proceed)
    skip_prompt = force or not sys.stdin.isatty() or network != "mainnet"
    try:
        sync_manager = SyncManager(data_dir, network)
        is_synced = sync_manager.is_synced()
        del sync_manager  # Release RocksDB lock before node opens it
        if not is_synced:
            console.print(
                "[yellow]⚠ Blockchain not fully synced — run 'ouroboros sync' first[/yellow]"
            )
            if not skip_prompt and not click.confirm("Continue anyway?", default=False):
                return
    except Exception as e:
        console.print(f"[yellow]⚠ Could not check sync status: {e}[/yellow]")
        if not skip_prompt and not click.confirm("Continue anyway?", default=False):
            return

    # Create and start node
    try:
        config_path = ctx.obj.get("config_path", str(Path(data_dir) / "ouroboros.conf"))
        config = {
            "datadir": data_dir,
            "network": network,
            "rpc_port": rpc_port,
            "p2p_port": p2p_port,
            "listen": listen,
            "config_path": config_path,
        }
        if connect:
            config["connect"] = list(connect)
        # --dnsseed/--nodnsseed: only override the conf-file value when the
        # operator explicitly passed the flag (Click leaves it None otherwise).
        # -connect forces DNS off downstream regardless of this value.
        if dnsseed is not None:
            config["dnsseed"] = bool(dnsseed)
        # Only override the conf-file value when the operator explicitly
        # passed --v2transport / --nov2transport.  Click leaves the option
        # at None when the flag was omitted so the conf file's value
        # (which itself defaults to enabled) wins.
        if v2transport is not None:
            config["v2transport"] = bool(v2transport)
        # Same conf-vs-CLI precedence for --peerbloomfilters.  When the
        # operator omits the flag the conf-file value (default off, Core
        # parity) wins.
        if peerbloomfilters is not None:
            config["peerbloomfilters"] = bool(peerbloomfilters)
        # Same conf-vs-CLI precedence for --blockfilterindex.  Default off
        # (Core parity, DEFAULT_BLOCKFILTERINDEX=false).
        if blockfilterindex is not None:
            config["blockfilterindex"] = bool(blockfilterindex)
        # --cfilter=N (alias):  0 = off, 1 = basic filter index.  Maps onto
        # the same config key as --blockfilterindex; explicit
        # --blockfilterindex wins when both are provided so the boolean
        # variant remains the canonical control surface.
        if cfilter is not None and blockfilterindex is None:
            if cfilter not in (0, 1):
                raise click.BadParameter(
                    f"--cfilter must be 0 (off) or 1 (basic), got {cfilter}"
                )
            config["blockfilterindex"] = bool(cfilter)
        # Same conf-vs-CLI precedence for --coinstatsindex.  Default off
        # (Core parity, DEFAULT_COINSTATSINDEX=false).  When the operator
        # omits the flag the conf-file value wins.
        if coinstatsindex is not None:
            config["coinstatsindex"] = bool(coinstatsindex)
        # Same conf-vs-CLI precedence for --txospenderindex.  Default off
        # (Core parity, DEFAULT_TXOSPENDERINDEX=false).  When the operator
        # omits the flag the conf-file value wins.
        if txospenderindex is not None:
            config["txospenderindex"] = bool(txospenderindex)

        # FIX-64: HTTPS/TLS termination flags.  Reject mismatched pairs at
        # the CLI layer so the operator sees a clean Click error rather than
        # a downstream ValueError from RPCServer.__init__.  Both-or-neither.
        if (rpc_tls_cert is None) != (rpc_tls_key is None):
            raise click.BadParameter(
                "--rpc-tls-cert and --rpc-tls-key must be provided together "
                "(both or neither)."
            )
        if rpc_tls_cert and rpc_tls_key:
            config["rpc_tls_cert"] = rpc_tls_cert
            config["rpc_tls_key"] = rpc_tls_key

        # Daemonize BEFORE writing the PID file so the recorded PID is
        # the post-fork process (parity with Bitcoin Core).
        if daemon:
            # If the operator didn't explicitly ask for console logging,
            # silence stderr in the daemonized child — file logging
            # remains active via the rotating handler installed by the
            # ``cli`` group.
            print_to_console_explicit = ctx.obj.get("print_to_console_explicit")
            if print_to_console_explicit is None or print_to_console_explicit is False:
                from ouroboros.logging_config import configure_logging
                configure_logging(
                    debug=ctx.obj.get("debug", False),
                    json_format=ctx.obj.get("log_json", False),
                    log_file=str(Path(data_dir) / "ouroboros.log"),
                    debug_categories=ctx.obj.get("debug_categories"),
                    print_to_console=False,
                )
            try:
                daemonize()
            except Exception as e:
                console.print(f"[red]✗ Failed to daemonize: {e}[/red]")
                sys.exit(1)

        # PID file: default location under datadir; written post-fork so
        # the recorded PID matches the running process.
        pid_target = pid_path or str(Path(data_dir) / "ouroboros.pid")
        _pid_file = PidFile(pid_target)
        try:
            _pid_file.write()
        except Exception as e:
            # Don't take down the node over a stale PID file race —
            # log loudly and continue.  Operators reading the file will
            # see the warning in the rotating log.
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "Could not write PID file %s: %s", pid_target, e
            )

        _node = BitcoinNode(config=config)

        # Tell systemd we're up (best-effort; no-op when NOTIFY_SOCKET
        # isn't set, i.e. not running under systemd).
        sd_notify_status("starting node")

        # Run node (blocks until Ctrl+C — status panel shown when ready)
        try:
            sd_notify_ready("ouroboros up")
            asyncio.run(_node.run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down node...[/yellow]")
            asyncio.run(_node.stop())
            console.print("[green]✓ Node stopped gracefully[/green]")
        finally:
            sd_notify_stopping("ouroboros stopped")
            if _pid_file is not None:
                try:
                    _pid_file.remove()
                except Exception:
                    pass

    except Exception as e:
        console.print(f"[red]✗ Error starting node: {e}[/red]")
        if _pid_file is not None:
            try:
                _pid_file.remove()
            except Exception:
                pass
        sys.exit(1)


@cli.command()
@click.pass_context
def status(ctx):
    """Show node status"""
    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]

    table = Table(title="Node Status", show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    # Network info
    table.add_row("Network", network)
    table.add_row("Data directory", data_dir)

    # Sync status
    try:
        sync_manager = SyncManager(data_dir, network)
        is_synced = sync_manager.is_synced()

        if is_synced:
            table.add_row("Sync status", "[green]✓ Synced[/green]")
        else:
            table.add_row("Sync status", "[yellow]⚠ Not synced[/yellow]")

        progress = sync_manager.get_progress()
        if progress:
            table.add_row("Current height", f"{progress.current_height:,}")
            table.add_row("Total height", f"{progress.total_height:,}")
            table.add_row("Progress", f"{progress.progress_percent:.2f}%")
    except Exception as e:
        table.add_row("Sync status", f"[red]Error: {e}[/red]")

    # Blockchain info
    try:
        db = BlockchainDatabase(data_dir)
        best_hash, best_height = db.get_best_block()
        table.add_row("Best block height", f"{best_height:,}")
        table.add_row("Best block hash", best_hash.hex()[:16] + "...")
    except Exception as e:
        table.add_row("Blockchain info", f"[red]Error: {e}[/red]")

    # Mempool info
    try:
        mempool = Mempool()
        tx_count = len(mempool.get_all_transactions())
        table.add_row("Mempool transactions", f"{tx_count}")
    except Exception as e:
        table.add_row("Mempool info", f"[red]Error: {e}[/red]")

    console.print(table)


@cli.command()
@click.argument("address")
@click.option("--network", default="mainnet", help="Network (mainnet/testnet)")
@click.pass_context
def getbalance(ctx, address, network):
    """Get balance for address"""
    data_dir = ctx.obj["data_dir"]

    console.print(f"[cyan]Getting balance for address: {address}[/cyan]")

    try:
        db = BlockchainDatabase(data_dir)
        balance_sat = db.get_balance(address, network)
        balance_btc = balance_sat / 100_000_000
        console.print(f"[green]Balance: {balance_btc:.8f} BTC ({balance_sat} satoshis)[/green]")
    except ValueError as e:
        console.print(f"[red]✗ Invalid address: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error getting balance: {e}[/red]")
        sys.exit(1)


@cli.command("import-utxo")
@click.argument("snapshot_path", type=click.Path(exists=True))
@click.option(
    "--batch-size",
    default=100_000,
    type=int,
    help="Number of UTXOs per WriteBatch flush (default 100K)",
)
@click.pass_context
def import_utxo(ctx, snapshot_path, batch_size):
    """Import a UTXO snapshot in Bitcoin Core's dumptxoutset v2 format.

    This loads a pre-generated UTXO set so the node can start syncing near the
    chain tip instead of doing full IBD. The existing chainstate is cleared
    before import.

    SNAPSHOT_PATH is the path to a snapshot file emitted by Core's
    `dumptxoutset` RPC (or any compatible producer including ouroboros'
    own dumptxoutset). The legacy HDOG format is no longer supported.
    """
    import sync

    from ouroboros.snapshot import (
        NETWORK_MAGIC,
        SnapshotManager,
        get_assumeutxo_by_hash,
        read_snapshot_metadata,
    )

    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]

    console.print(
        f"[bold]ouroboros import-utxo[/bold] -- [cyan]{network}[/cyan]\n"
        f"[dim]Data: {data_dir}  Snapshot: {snapshot_path}[/dim]"
    )

    # Read & validate metadata (Core format).
    try:
        metadata = read_snapshot_metadata(snapshot_path, network)
    except Exception as e:
        console.print(f"[red]Invalid snapshot: {e}[/red]")
        sys.exit(1)

    # Resolve height from the assumeutxo blockhash table.
    au_data = get_assumeutxo_by_hash(network, metadata.base_blockhash)
    if au_data is None and network != "regtest":
        console.print(
            f"[red]assumeUTXO blockhash {metadata.base_blockhash_hex()} not "
            f"recognized for network {network}.[/red]"
        )
        sys.exit(1)
    block_height = au_data.height if au_data else 0

    console.print(
        f"  Version:    [cyan]{metadata.version}[/cyan]\n"
        f"  Block hash: [cyan]{metadata.base_blockhash_hex()}[/cyan]\n"
        f"  Height:     [cyan]{block_height:,}[/cyan]\n"
        f"  UTXOs:      [cyan]{metadata.coins_count:,}[/cyan]\n"
        f"  Batch size: [cyan]{batch_size:,}[/cyan]"
    )

    # Confirm
    if sys.stdin.isatty():
        if not click.confirm(
            f"This will CLEAR the existing chainstate and load "
            f"{metadata.coins_count:,} UTXOs. Continue?",
            default=True,
        ):
            console.print("[yellow]Aborted.[/yellow]")
            return

    # Open DB and delegate to Rust.  Use the Python BlockchainDatabase
    # wrapper (it holds the single PyBlockchainDB handle internally as
    # ``._db``) so we can drive both the Rust import AND the Python-side
    # snapshot-base index persist over ONE RocksDB handle — a second
    # PyBlockchainDB over the same datadir would deadlock on the
    # single-writer lock.
    from ouroboros.database import BlockchainDatabase

    try:
        db = BlockchainDatabase(data_dir)
    except Exception as e:
        console.print(f"[red]Failed to open database: {e}[/red]")
        sys.exit(1)

    expected_magic = NETWORK_MAGIC.get(network)
    expected_magic_arg = list(expected_magic) if expected_magic is not None else None

    start_time = time.time()
    try:
        block_hash_hex, height, loaded = db._db.import_core_snapshot(
            snapshot_path, block_height, expected_magic_arg, batch_size
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Import interrupted[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        sys.exit(1)

    # The Rust import writes only the UTXO set + tip pointer.  Persist the
    # snapshot base block index (sibling header files + BLOCK_INDEX
    # metadata row) so the FIRST block above the snapshot (height+1) has a
    # connectable parent — without this the forward-sync rejects it with
    # "Previous block not found" forever.  This mirrors the Python
    # loadtxoutset commit path; see SnapshotManager.persist_snapshot_base_index.
    try:
        sm = SnapshotManager(db, network, data_dir)
        persisted = sm.persist_snapshot_base_index(metadata.base_blockhash)
        if persisted:
            console.print(
                "  [dim]Snapshot base index persisted "
                f"(height {height}) — forward-sync can connect {height + 1}.[/dim]"
            )
        else:
            console.print(
                "  [yellow]No base header in chainparams for this snapshot; "
                "the base header must be supplied by header-sync before the "
                "first post-snapshot block can connect.[/yellow]"
            )
    except Exception as e:
        console.print(
            f"  [yellow]Warning: failed to persist snapshot base index: {e}[/yellow]\n"
            "  [yellow]The first post-snapshot block may fail to connect.[/yellow]"
        )

    elapsed = time.time() - start_time
    rate = loaded / max(elapsed, 0.001)
    console.print(
        f"\n[green]Import complete[/green]\n"
        f"  UTXOs loaded: [cyan]{loaded:,}[/cyan]\n"
        f"  Chain tip:    [cyan]{height:,}[/cyan] ({block_hash_hex[:16]}...)\n"
        f"  Elapsed:      [cyan]{elapsed:.1f}s[/cyan]  ({rate:,.0f} utxo/s)"
    )


@cli.command("import-blocks")
@click.argument("source", default="-", type=click.Path(exists=False))
@click.pass_context
def import_blocks(ctx, source):
    """Import blocks from a framed binary file (or stdin with -)

    Frame format: [4 bytes height LE] [4 bytes size LE] [size bytes raw block]
    """
    import struct

    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]

    console.print(
        f"[bold]ouroboros import-blocks[/bold] -- [cyan]{network}[/cyan]\n"
        f"[dim]Data: {data_dir}  Source: {source}[/dim]"
    )

    if sync is None:
        console.print("[red]Rust sync module not available. Install with: maturin develop[/red]")
        sys.exit(1)

    # Open the database
    try:
        db = sync.PyBlockchainDB(data_dir)
    except Exception as e:
        console.print(f"[red]Failed to open database: {e}[/red]")
        sys.exit(1)

    # Get current tip height
    try:
        _best_hash, tip_height = db.get_best_block()
    except Exception:
        tip_height = 0

    console.print(f"Chain tip at height [cyan]{tip_height:,}[/cyan], starting import")

    # Try the fast Rust-native path for file sources (reads the framed
    # format entirely in Rust, avoiding Python I/O overhead).
    use_rust_native = source != "-" and hasattr(db, "import_blocks_from_file")

    if use_rust_native:
        console.print("[dim]Using Rust-native file reader[/dim]")
        start_time = time.time()
        try:
            imported = db.import_blocks_from_file(source, tip_height, 10000)
        except KeyboardInterrupt:
            console.print("\n[yellow]Import interrupted[/yellow]")
            return
        except Exception as e:
            console.print(f"[red]Error during import: {e}[/red]")
            sys.exit(1)

        elapsed = time.time() - start_time
        rate = imported / max(elapsed, 0.001)
        console.print(
            f"\n[green]Import complete: {imported:,} blocks imported[/green]\n"
            f"[dim]Elapsed: {elapsed:.1f}s  Rate: {rate:.1f} blk/s[/dim]"
        )
        return

    # Fallback: Python-side stdin reader
    if source == "-":
        input_file = sys.stdin.buffer
    else:
        try:
            input_file = open(source, "rb")
        except OSError as e:
            console.print(f"[red]Cannot open file: {e}[/red]")
            sys.exit(1)

    imported = 0
    skipped = 0
    start_time = time.time()
    last_log_time = start_time

    try:
        while True:
            # Read frame header: [4 bytes height LE] [4 bytes size LE]
            frame_header = input_file.read(8)
            if not frame_header:
                break
            if len(frame_header) < 8:
                console.print(f"[red]Incomplete frame header: got {len(frame_header)} bytes[/red]")
                break

            frame_height, frame_size = struct.unpack("<II", frame_header)

            if frame_size == 0 or frame_size > 4 * 1024 * 1024:
                console.print(f"[red]Invalid frame size {frame_size} at height {frame_height}[/red]")
                break

            # Read block data
            block_data = input_file.read(frame_size)
            if len(block_data) < frame_size:
                console.print(
                    f"[red]Incomplete block at height {frame_height}: "
                    f"got {len(block_data)} of {frame_size}[/red]"
                )
                break

            # Skip blocks we already have
            if frame_height <= tip_height:
                skipped += 1
                continue

            # Connect block via Rust
            try:
                db.connect_block_from_bytes(block_data, frame_height)
            except Exception as e:
                console.print(f"[red]Error connecting block at height {frame_height}: {e}[/red]")
                sys.exit(1)

            imported += 1

            # Log progress periodically
            now = time.time()
            if now - last_log_time >= 10 or imported % 10000 == 0:
                elapsed = now - start_time
                rate = imported / max(elapsed, 0.001)
                console.print(
                    f"[dim]import-blocks: height={frame_height} "
                    f"imported={imported:,} skipped={skipped:,} "
                    f"rate={rate:.1f} blk/s[/dim]"
                )
                last_log_time = now

    except KeyboardInterrupt:
        console.print("\n[yellow]Import interrupted[/yellow]")
    finally:
        if source != "-" and hasattr(input_file, "close"):
            input_file.close()

    elapsed = time.time() - start_time
    rate = imported / max(elapsed, 0.001)
    console.print(
        f"\n[green]Import complete: {imported:,} blocks imported, "
        f"{skipped:,} skipped[/green]\n"
        f"[dim]Elapsed: {elapsed:.1f}s  Rate: {rate:.1f} blk/s[/dim]"
    )


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
