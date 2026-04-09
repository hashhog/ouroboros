# ---------- build ----------
FROM python:3.12-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gcc g++ make pkg-config \
        libssl-dev libclang-dev librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install --no-cache-dir maturin

WORKDIR /src
COPY . .
RUN maturin build --release --manifest-path ferrous-utils/sync/Cargo.toml && \
    pip install --no-cache-dir target/wheels/*.whl && \
    pip install --no-cache-dir .

# ---------- runtime ----------
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        librocksdb7.8 libssl3 libsecp256k1-1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin

VOLUME /data
EXPOSE 48350 48340

ENTRYPOINT ["python3", "-m", "ouroboros.cli"]
CMD ["--data-dir=/data", "--network=testnet4", "start"]
