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
    TaskID,
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
@click.pass_context
def cli(ctx, data_dir, config_file, network):
    """Bitcoin Hybrid Node - Rust sync, Python operations"""
    # OROBOROS_DATADIR overrides --data-dir
    if os.environ.get("OUROBOROS_DATADIR"):
        data_dir = str(expand_path(os.environ["OUROBOROS_DATADIR"]))
    # Ensure data directory exists
    Path(data_dir).mkdir(parents=True, exist_ok=True)
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
    
    limit_info = f"\nBlock limit: [cyan]{limit}[/cyan]" if limit else ""
    console.print(Panel.fit(
        f"[bold]Blockchain Synchronization[/bold]\n"
        f"Network: [cyan]{network}[/cyan]\n"
        f"Data directory: [cyan]{data_dir}[/cyan]"
        f"{limit_info}",
        border_style="blue"
    ))
    
    # Create SyncManager
    try:
        _sync_manager = SyncManager(data_dir, network)
    except Exception as e:
        console.print(f"[red]Error initializing sync manager: {e}[/red]")
        sys.exit(1)
    
    # Check if already synced
    if _sync_manager.is_synced():
        console.print("[green]✓ Blockchain is already synchronized[/green]")
        return
    
    # Progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[cyan]{task.fields[blocks]}[/cyan]"),
        TextColumn("[yellow]{task.fields[speed_str]}[/yellow]"),
        console=console,
    ) as progress:
        # TODO: Peer count and desync warnings - expose from Rust BlockProgressCache when available
        task = progress.add_task(
            "[cyan]Phase: Header sync • Starting...[/cyan]",
            total=100.0,
            blocks="0",
            speed_str="",
        )
        
        _last_phase: Optional[str] = None

        def progress_callback(prog: SyncProgress):
            """Update progress bar with sync status."""
            nonlocal _last_phase
            global _cancelled
            if _cancelled:
                return

            # Reset progress bar when transitioning from header to block phase
            if prog.phase == "block" and _last_phase == "header":
                progress.update(task, completed=0)
            _last_phase = prog.phase

            # Block count display: "X blocks / chain_height" during block phase, "X headers" during header
            if prog.phase == "block":
                blocks_str = (
                    f"{prog.current_height:,} blocks / {prog.total_height:,}"
                    if prog.total_height > 0
                    else f"{prog.current_height:,} blocks"
                )
                speed_str = f" • {prog.blocks_per_second:.1f} blocks/s • "
            else:
                blocks_str = f"{prog.current_height:,} headers"
                speed_str = " • "

            # Update progress
            progress.update(
                task,
                completed=prog.progress_percent,
                blocks=blocks_str,
                speed_str=speed_str,
            )

            # Description with phase label (blocks/speed in columns to avoid duplication)
            if prog.phase == "header":
                if not prog.total_known:
                    desc = "[cyan]Phase: Header sync • Requesting current block height...[/cyan]"
                else:
                    desc = f"[cyan]Phase: Header sync • {prog.current_height:,} headers[/cyan]"
            else:
                # Block phase: phase label + ETA
                if prog.eta_seconds >= 999 * 3600:
                    eta_str = "—"
                elif prog.eta_seconds < 60:
                    eta_str = f"{prog.eta_seconds}s"
                elif prog.eta_seconds < 3600:
                    eta_str = f"{prog.eta_seconds // 60}m {prog.eta_seconds % 60}s"
                else:
                    hours = prog.eta_seconds // 3600
                    minutes = (prog.eta_seconds % 3600) // 60
                    eta_str = f"{hours}h {minutes}m"
                desc = f"[cyan]Phase: Block sync • ETA: {eta_str}[/cyan]"

            progress.update(task, description=desc)
        
        def cancel_check() -> bool:
            """Check if sync should be cancelled."""
            return _cancelled

        def format_duration(secs: float) -> str:
            """Format duration for display."""
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
                progress_interval=1.0,  # Update every second for better UX
                limit=limit,
            )

            if success:
                progress.update(task, completed=100.0)
                duration_secs = time.time() - sync_start_time
                final_progress = _sync_manager.get_progress() or _sync_manager.last_progress
                final_height = final_progress.current_height if final_progress else 0
                console.print(
                    "\n[green]✓ Blockchain synchronization completed[/green] "
                    f"• Height: [cyan]{final_height:,}[/cyan] "
                    f"• Duration: [cyan]{format_duration(duration_secs)}[/cyan]"
                )
            elif _cancelled:
                console.print("\n[yellow]Synchronization cancelled by user[/yellow]")
            else:
                error = _sync_manager.last_error
                console.print(f"\n[red]✗ Synchronization failed: {error}[/red]")
                sys.exit(1)
        
        except KeyboardInterrupt:
            _cancelled = True
            _sync_manager.cancel_sync()
            console.print("\n[yellow]Synchronization interrupted[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]✗ Error during synchronization: {e}[/red]")
            sys.exit(1)


@cli.command()
@click.pass_context
@click.option("--rpc-port", default=8332, type=int, help="RPC server port")
@click.option("--p2p-port", default=8333, type=int, help="P2P network port")
def start(ctx, rpc_port, p2p_port):
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
    
    # Check if synced
    try:
        sync_manager = SyncManager(data_dir, network)
        if not sync_manager.is_synced():
            console.print(
                "[yellow]⚠ Blockchain not fully synced — run 'ouroboros sync' first[/yellow]"
            )
            if not click.confirm("Continue anyway?", default=False):
                return
    except Exception as e:
        console.print(f"[yellow]⚠ Could not check sync status: {e}[/yellow]")
        if not click.confirm("Continue anyway?", default=False):
            return
    
    # Create and start node
    try:
        config_path = ctx.obj.get("config_path", str(Path(data_dir) / "ouroboros.conf"))
        config = {
            "datadir": data_dir,
            "network": network,
            "rpc_port": rpc_port,
            "p2p_port": p2p_port,
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
