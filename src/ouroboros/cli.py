"""Command-line interface for the Bitcoin node."""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import click
from ouroboros.node import BitcoinNode


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """Ouroboros - A Bitcoin node implementation."""
    pass


@cli.command()
@click.option(
    "--datadir",
    type=click.Path(path_type=Path),
    default=Path.home() / ".ouroboros",
    help="Data directory for the node",
)
@click.option(
    "--network",
    type=click.Choice(["mainnet", "testnet", "regtest"]),
    default="mainnet",
    help="Bitcoin network to connect to",
)
@click.option(
    "--rpc-port",
    type=int,
    default=8332,
    help="RPC server port",
)
@click.option(
    "--p2p-port",
    type=int,
    default=8333,
    help="P2P network port",
)
def start(
    datadir: Path,
    network: str,
    rpc_port: int,
    p2p_port: int,
) -> None:
    """Start the Bitcoin node."""
    click.echo(f"Starting Ouroboros Bitcoin node...")
    click.echo(f"  Network: {network}")
    click.echo(f"  Data directory: {datadir}")
    click.echo(f"  RPC port: {rpc_port}")
    click.echo(f"  P2P port: {p2p_port}")
    
    config = {
        "datadir": str(datadir),
        "network": network,
        "rpc_port": rpc_port,
        "p2p_port": p2p_port,
    }
    
    node = BitcoinNode(config=config)
    
    try:
        asyncio.run(node.run())
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
        asyncio.run(node.stop())


@cli.command()
def status() -> None:
    """Show node status."""
    click.echo("Node status: Not running")
    # TODO: Implement status check


@cli.command()
@click.option(
    "--datadir",
    type=click.Path(path_type=Path),
    default=Path.home() / ".ouroboros",
    help="Data directory for the node",
)
def init(datadir: Path) -> None:
    """Initialize the node data directory."""
    click.echo(f"Initializing data directory: {datadir}")
    datadir.mkdir(parents=True, exist_ok=True)
    click.echo("✓ Data directory initialized")


@cli.group()
def wallet() -> None:
    """Wallet management commands."""
    pass


@wallet.command()
@click.option("--name", default="default", help="Wallet name")
def create(name: str) -> None:
    """Create a new wallet."""
    click.echo(f"Creating wallet: {name}")
    # TODO: Implement wallet creation


@wallet.command()
def list() -> None:
    """List all wallets."""
    click.echo("Wallets:")
    # TODO: Implement wallet listing


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

