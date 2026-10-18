# Building ouroboros

ouroboros has two parts: the Python package `ouroboros` (in `src/`) and a Rust extension module named `sync` (in `ferrous-utils/sync/`), built with [maturin](https://www.maturin.rs/) and loaded by Python through PyO3. The node needs both.

## Toolchain

| Tool | Version | Notes |
|---|---|---|
| Python | 3.11, 3.12 or 3.13 | `requires-python = ">=3.11,<3.14"` in `pyproject.toml`. Tested with 3.13.5. |
| Rust | stable | No `rust-version` pin; edition 2021. Tested with 1.99.0. |
| maturin | 1.x | Installed with pip inside the virtualenv. Tested with 1.15.0. |
| C/C++ compiler and clang | any recent | RocksDB, zstd, lz4, bzip2 and zlib are compiled from source by their `-sys` crates; `bindgen` needs `libclang`. |

On Debian or Ubuntu:

```bash
sudo apt-get install -y build-essential clang libclang-dev pkg-config python3-dev python3-venv git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . "$HOME/.cargo/env"
```

No system RocksDB or libsecp256k1 is needed: RocksDB 10.4 is built into the extension, the Rust side uses the `secp256k1` crate's bundled copy, and the Python side uses `coincurve`'s wheel. The finished extension links only against the C and C++ runtime libraries.

## Build

From the repository root:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install maturin
maturin build --release --manifest-path ferrous-utils/sync/Cargo.toml
pip install target/wheels/*.whl
pip install -e '.[dev]'
```

The first `maturin build` takes about 27 CPU-minutes (two minutes of wall time on a 16-core machine), most of it compiling RocksDB. The wheel lands in `target/wheels/` because `Cargo.toml` at the root is a Cargo workspace. `pip install -e .` installs the Python package in editable mode, so changes under `src/` take effect without reinstalling; changes under `ferrous-utils/` need the `maturin build` and wheel install again. The `[dev]` extra adds pytest, pytest-asyncio, httpx, ruff, black and mypy.

To check the result:

```bash
python -c "import sync, ouroboros; print(sync.__file__)"
ouroboros --help
```

`setup.sh` does the same steps interactively (it calls `sudo apt-get` and `rustup update`). The commands above are the ones these docs were tested with.

## Build options

There are no Cargo features to choose between. Two behaviours are picked at run time, not at build time:

- `OUROBOROS_NATIVE_SCRIPT=1` sends script verification through the Rust port of Core's interpreter in `ferrous-utils/sync/src/validate/interpreter.rs` instead of the Python one in `src/ouroboros/script.py`. If the installed extension lacks it, the node refuses to start rather than falling back to Python. See [running.md](running.md#environment-variables).
- `OUROBOROS_DISABLE_RUST_VALIDATE=1` makes block-level checks run in Python instead of the Rust fast path.

## Reproducibility

`Cargo.lock` is committed, so the Rust dependency versions are fixed. Python dependencies are lower bounds only (`pyproject.toml` has no lock file), so two builds on different days can pull different versions of FastAPI, uvicorn and the other Python packages. Builds are not reproducible bit for bit.
