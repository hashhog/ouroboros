# Contributing to ouroboros

Thank you for helping. ouroboros is a from-scratch Bitcoin node, so correctness matters more than features or speed.

## Build and test

See [docs/building.md](docs/building.md) for the Python and Rust toolchains. Then, inside the virtualenv:

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git bitcoin
python -m pytest
```

Before opening a pull request, run the suite and check that your change adds no failures; [docs/status.md](docs/status.md#test-suite) lists the failures already on `master`. For a change to the script interpreter, also run Core's vectors with `python -m pytest -s tests/test_script_vectors.py` and `python tests/test_sighash_vectors.py`. A change under `ferrous-utils/` needs the `maturin build` and wheel install from building.md before the tests see it.

## Pull requests

- Every behaviour change comes with a test that fails before the change and passes after it. Name the test in the pull request description.
- Put tests in `tests/test_<topic>.py`. Most tests run against the stand-in for the Rust extension that `tests/conftest.py` installs; a test that needs the real extension must say so and skip when it is missing.
- Keep each pull request to one change. Refactors go in their own pull request.
- Do not disable, skip or delete a test without explaining why in the pull request.
- Format Python with `black` and check it with `ruff` (settings in `pyproject.toml`); format Rust with `cargo fmt`.
- Branch from and target `master`.

## Commit messages

Use a conventional prefix and explain why the change is needed, not only what it does:

```
fix(rpc): return -8 for an out-of-range height in getblockhash

Core returns RPC_INVALID_PARAMETER (-8) here; we returned -1, which broke
clients that match on the code.
```

Common prefixes: `fix`, `feat`, `perf`, `refactor`, `test`, `docs`, `chore`. A scope in parentheses (`consensus`, `p2p`, `rpc`, `storage`, `wallet`) helps reviewers.

## Consensus changes

Anything that can change whether a block or transaction is accepted (script, validation, UTXO handling, chain selection, reorganisations) needs evidence that ouroboros behaves like Bitcoin Core afterwards. Point to the Core source that defines the behaviour, add a test with the concrete input (Core's test vectors where they exist), and describe how the change could make a valid block invalid or an invalid block valid, and which test covers that. If the change touches both the Python and the Rust implementation of a check, test both. Where possible, show the same input on Core and on ouroboros giving the same result, for example on regtest as in [docs/status.md](docs/status.md).
