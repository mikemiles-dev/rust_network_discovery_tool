## 1. Parallel instance detection

- [x] 1.1 In `detect_existing_instance()` (src/web/mod.rs lines 39-57), replace the sequential `for &port in ports` loop with `std::thread::scope` that spawns one thread per port, each checking `http://127.0.0.1:{port}/api/instance` concurrently; collect results and return the first match found
- [x] 1.2 Reduce the `reqwest::blocking::Client` timeout from 500ms to 200ms (line 41)

## 2. Parallel startup init

- [x] 2.1 In `main()` (src/main.rs), move the `MDnsLookup::start_daemon()` call (line 376) to before `SQLWriter::new().await` (line 374), so mDNS discovery starts during DB initialization

## 3. Validation

- [x] 3.1 Verify `cargo check` succeeds
- [x] 3.2 Verify `cargo clippy` has no new warnings
- [x] 3.3 Verify `cargo test` passes
