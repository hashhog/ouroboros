"""Command-line interface for the Bitcoin node."""

import asyncio
import os
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
)
from rich.table import Table
from rich.panel import Panel

from ouroboros.sync_manager import SyncManager, SyncProgress
from ouroboros.node import BitcoinNode
from ouroboros.database import BlockchainDatabase
from ouroboros.mempool import Mempool

console = Console()

# Global variables for signal handling
_sync_manager: Optional[SyncManager] = None
_node: Optional[BitcoinNode] = None
_cancelled = False
_interruption_shown = False


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
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--log-json", is_flag=True, help="Emit structured JSON log lines")
@click.pass_context
def cli(ctx, data_dir, config_file, network, debug, log_json):
    """Bitcoin Hybrid Node - Rust sync, Python operations"""
    from ouroboros.logging_config import configure_logging

    # OROBOROS_DATADIR overrides --data-dir
    if os.environ.get("OUROBOROS_DATADIR"):
        data_dir = str(expand_path(os.environ["OUROBOROS_DATADIR"]))
    # Ensure data directory exists
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    # Wire --debug through to Rust logging (OUROBOROS_VERBOSE=1 sets sync=debug)
    if debug:
        os.environ["OUROBOROS_VERBOSE"] = "1"

    configure_logging(
        debug=debug,
        json_format=log_json,
        log_file=str(Path(data_dir) / "ouroboros.log") if not debug else None,
    )

    # Config path: --config or data_dir/ouroboros.conf
    config_path = config_file or str(Path(data_dir) / "ouroboros.conf")
    ctx.obj = {
        "data_dir": data_dir,
        "network": network,
        "config_path": config_path,
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

        _last_phase: Optional[str] = None
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
@click.option("--force", is_flag=True, default=False, help="Skip sync check prompt")
@click.pass_context
def start(ctx, rpc_port, p2p_port, listen, force):
    """Start the Bitcoin node"""
    global _node, _cancelled
    _cancelled = False
    
    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]
    
    console.print(Panel.fit(
        f"[bold]Starting Bitcoin Node[/bold]\n"
        f"Network: [cyan]{network}[/cyan]\n"
        f"Data directory: [cyan]{data_dir}[/cyan]\n"
        f"RPC port: [cyan]{rpc_port}[/cyan] | P2P port: [cyan]{p2p_port}[/cyan]\n\n"
        f"[dim]Node will display status when ready. Press Ctrl+C to stop.[/dim]",
        border_style="green"
    ))
    
    # Check if synced (release SyncManager before node opens DB to avoid RocksDB lock conflict)
    try:
        sync_manager = SyncManager(data_dir, network)
        is_synced = sync_manager.is_synced()
        del sync_manager  # Release RocksDB lock before node opens it
        if not is_synced:
            console.print(
                "[yellow]⚠ Blockchain not fully synced — run 'ouroboros sync' first[/yellow]"
            )
            if not force and not click.confirm("Continue anyway?", default=False):
                return
    except Exception as e:
        console.print(f"[yellow]⚠ Could not check sync status: {e}[/yellow]")
        if not force and not click.confirm("Continue anyway?", default=False):
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
        
        _node = BitcoinNode(config=config)

        # Run node (blocks until Ctrl+C — status panel shown when ready)
        try:
            asyncio.run(_node.run())
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down node...[/yellow]")
            asyncio.run(_node.stop())
            console.print("[green]✓ Node stopped gracefully[/green]")
    
    except Exception as e:
        console.print(f"[red]✗ Error starting node: {e}[/red]")
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


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
