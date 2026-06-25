# Lantern under Shadow

Support for running Lantern under the [Shadow](https://shadow.github.io/) simulator. Opt-in:
production builds are unaffected and the sim-cost model is a no-op unless its rates are set.

## Build

A Shadow build is the production build with two switches flipped off:

```sh
docker buildx build -f shadow/Dockerfile.shadow -t lantern:shadow .
```

or locally:

```sh
cmake -S . -B build-shadow \
  -DLANTERN_C_LEANVM_XMSS_JEMALLOC=OFF \
  -DLANTERN_C_LEAN_LIBP2P_AWSLC_CPU_JITTER_ENTROPY=OFF
cmake --build build-shadow --target lantern_cli
```

- `JEMALLOC=OFF` drops the jemalloc global allocator (it deadlocks Shadow's shim, [shadow#3763](https://github.com/shadow/shadow/issues/3763)).
- `AWSLC_CPU_JITTER_ENTROPY=OFF` disables aws-lc's CPU-jitter entropy source.

## Run

Set these in each node's Shadow process environment:

```sh
OPENSSL_ia32cap=~0x4000000000000000:~0x00040000   # masks RDRAND/RDSEED so aws-lc uses getrandom
LANTERN_SHADOW_XMSS_AGGREGATE_RATE=<sigs/sec>      # optional prover-cost model; unset = off
LANTERN_SHADOW_XMSS_VERIFY_RATE=<sigs/sec>
LANTERN_SHADOW_XMSS_MERGE_RATE=<components/sec>
```

The simulation harness is in `lean-quickstart` (`tools/lean-quickstart`, branch
`feat/shadow-automation`): it generates `shadow.yaml` and runs `shadow`. Inject the variables
above via the per-node environment so the normal lean-quickstart run is unchanged.

## Notes

- The jitter source is disabled at build time; RDRAND/RDSEED are masked at runtime via
  `OPENSSL_ia32cap`. With both off, aws-lc falls back to `getrandom`, which Shadow virtualizes.
  Confirm the mask once on a real x86_64 host.
- The sim-cost model (`src/consensus/shadow_cost.c`) sleeps `n / rate` ns after each real
  prove/verify/merge so prover cost shows on the virtual clock. Rates also accept CLI flags
  (`--shadow-xmss-*-rate`).
- QUIC needs no patch: Lantern's ngtcp2 UDP path uses plain `sendto`/`recvfrom` and none of the
  GSO/GRO/ECN options that the Rust and Go stacks patch around. Build against stock Shadow.
