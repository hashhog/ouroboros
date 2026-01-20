"""Command-line interface for the Bitcoin node."""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
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


def handle_sigint(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully."""
    global _cancelled, _sync_manager, _node
    _cancelled = True
    
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
    
    sys.exit(0)


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
    help="Data directory",
    callback=lambda ctx, param, value: str(expand_path(value)),
)
@click.option(
    "--network",
    default="mainnet",
    type=click.Choice(["mainnet", "testnet", "regtest"]),
    help="Bitcoin network",
)
@click.pass_context
def cli(ctx, data_dir, network):
    """Bitcoin Hybrid Node - Rust sync, Python operations"""
    # Ensure data directory exists
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    
    ctx.obj = {
        "data_dir": data_dir,
        "network": network,
    }


@cli.command()
@click.pass_context
def sync(ctx):
    """Synchronize blockchain (initial download)"""
    global _sync_manager, _cancelled
    _cancelled = False
    
    data_dir = ctx.obj["data_dir"]
    network = ctx.obj["network"]
    
    console.print(Panel.fit(
        f"[bold]Blockchain Synchronization[/bold]\n"
        f"Network: [cyan]{network}[/cyan]\n"
        f"Data directory: [cyan]{data_dir}[/cyan]",
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
        TextColumn("[cyan]{task.fields[blocks]}[/cyan] blocks"),
        TextColumn("•"),
        TextColumn("[yellow]{task.fields[speed]:.1f} blocks/s[/yellow]"),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Syncing blockchain...",
            total=100.0,
            blocks="0",
            speed=0.0,
        )
        
        def progress_callback(prog: SyncProgress):
            """Update progress bar with sync status."""
            global _cancelled
            if _cancelled:
                return
            
            # Update progress
            progress.update(
                task,
                completed=prog.progress_percent,
                blocks=f"{prog.current_height:,}/{prog.total_height:,}",
                speed=prog.blocks_per_second,
            )
            
            # Update description with ETA
            if prog.eta_seconds < 60:
                eta_str = f"{prog.eta_seconds}s"
            elif prog.eta_seconds < 3600:
                eta_str = f"{prog.eta_seconds // 60}m {prog.eta_seconds % 60}s"
            else:
                hours = prog.eta_seconds // 3600
                minutes = (prog.eta_seconds % 3600) // 60
                eta_str = f"{hours}h {minutes}m"
            
            progress.update(
                task,
                description=f"[cyan]Syncing blockchain... ETA: {eta_str}[/cyan]",
            )
        
        def cancel_check() -> bool:
            """Check if sync should be cancelled."""
            return _cancelled
        
        # Start sync
        try:
            success = _sync_manager.perform_initial_sync(
                progress_callback=progress_callback,
                cancel_check=cancel_check,
                progress_interval=1.0,
            )
            
            if success:
                progress.update(task, completed=100.0)
                console.print("\n[green]✓ Blockchain synchronization completed successfully![/green]")
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
        f"RPC port: [cyan]{rpc_port}[/cyan]\n"
        f"P2P port: [cyan]{p2p_port}[/cyan]",
        border_style="green"
    ))
    
    # Check if synced
    try:
        sync_manager = SyncManager(data_dir, network)
        if not sync_manager.is_synced():
            console.print(
                "[yellow]⚠ Warning: Blockchain is not fully synchronized. "
                "Run 'sync' command first to download the blockchain.[/yellow]"
            )
            if not click.confirm("Continue anyway?", default=False):
                return
    except Exception as e:
        console.print(f"[yellow]⚠ Could not check sync status: {e}[/yellow]")
        if not click.confirm("Continue anyway?", default=False):
            return
    
    # Create and start node
    try:
        config = {
            "datadir": data_dir,
            "network": network,
            "rpc_port": rpc_port,
            "p2p_port": p2p_port,
        }
        
        _node = BitcoinNode(config=config)
        
        console.print("[green]Starting node...[/green]")
        
        # Run node (this blocks until interrupted)
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
@click.pass_context
def getbalance(ctx, address):
    """Get balance for address"""
    data_dir = ctx.obj["data_dir"]
    
    console.print(f"[cyan]Getting balance for address: {address}[/cyan]")
    
    try:
        db = BlockchainDatabase(data_dir)
        
        # TODO: Implement balance calculation from UTXO set
        # For now, this is a placeholder
        console.print("[yellow]Balance calculation not yet implemented[/yellow]")
        console.print(
            "[dim]This requires scanning the UTXO set for outputs matching "
            "the address script pubkey.[/dim]"
        )
    
    except Exception as e:
        console.print(f"[red]✗ Error getting balance: {e}[/red]")
        sys.exit(1)


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
