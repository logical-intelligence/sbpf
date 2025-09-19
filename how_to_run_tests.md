## How to run tests:

- Go through `README.md` in `sbpf-emu` repository first.

### Running unit tests
- From this folder
```
# Primary test file
LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1 RUSTFLAGS="$RUSTFLAGS_LINK_ARGS" cargo test --test execution -- --test-threads=1

# Stress test for all arithmetic instructions
LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1 RUSTFLAGS="$RUSTFLAGS_LINK_ARGS" cargo test --test exercise_instructions -- --test-threads=1
```

### Running fuzzing
- Install cargo-fuzz first if you don't have it.
```
cargo install cargo-fuzz
```

- Go to `fuzz` folder.
```
cd fuzz
```

There are two fuzzing targets, corresponding to existing SBPF fuzzing targets `smart.rs` and `dumb.rs`.
```
LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1 RUSTFLAGS="$RUSTFLAGS_LINK_ARGS" cargo +nightly fuzz run smart_lean_diff
LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1 RUSTFLAGS="$RUSTFLAGS_LINK_ARGS" cargo +nightly fuzz run dumb_lean_diff
```

