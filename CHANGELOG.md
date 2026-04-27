## 1.1.0 - Release

- Improve logging:
  - Replace global `logging` module with new `CategoryLogger` class
  - Add 5 independent log categories with per-category log level: `startup`, `healthcheck`, `traffic`, `statistics`, `learning`
  - Remove `logging.level` (replaced by per-category levels)
  - Remove `logging.hex_dump`: hex dumps are always emitted via `traffic` category at `DEBUG` level
  - Health check output promoted from `DEBUG` to `INFO` via `healthcheck` category
  - Removed verbose internal debug noise (ASH parser byte traces, CRC debug output)
- Change `config.yaml`:
  - Add `logging` categories: `startup`, `healthcheck`, `traffic`, `statistics`, `learning`
  - Remove `logging.hex_dump`
  - Remove `logging.level`
  - Remove `routing:` block (routing mode remains configurable but removed from default config)
- Change `learning_state.json`:
  - Persisted immediately after every learning update (previously only on clean shutdown)
  - Extract `_write_learning_data_unlocked()` as internal write helper
- Fix: ZNP SRSP frames with non-zero status no longer dropped — forwarded to Z2M as valid frames
- Fix: EZSP NACK frames no longer treated as errors — forwarded as valid frames
- Fix: `expects_response` flag in smart mode disabled — primary stick owns full request/response flow without fan-in wait
- Fix: `_is_localhost_peer()` renamed to `_is_loopback_peer()`, now accepts full peer tuple instead of IP string
- Remove `_as_bool()` helper (no longer needed after `logging.hex_dump` removal)
- Update `README.md`: restructured, added logging category documentation, updated troubleshooting

## 1.0.2 - Hotfix
- Add mem_limit to docker-compose.yml
- Change logging and translations

## 1.0.1 - Hotfix
- Update README
- Change local directory to `/data`
- Modify docker-compose.yml:
  - `/data` mapping
  - build process

## 1.0.0 - Initialized
