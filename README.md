# Zigbee Multi-Stick Proxy (Python)

A TCP proxy for Zigbee2MQTT that accepts exactly one Z2M client and forwards requests to multiple SLZB sticks.

## What This Project Does

- A Z2M client connects to the proxy on port 6638.
- The proxy connects to multiple sticks in parallel.
- Requests are sent to one or more sticks depending on the routing mode.
- Responses are validated; in broadcast mode, the first valid response wins.
- Asynchronous stick events are deduplicated before being forwarded to Z2M.

## Architecture

```text
    Zigbee2MQTT (1 client)
               |
               v
+------------------------------+
|      Proxy (Port 6638)       |
|                              |
| - Request Queue              |
| - Retry / Timeout            |
| - Smart Failover             |
| - Response Arbitration       |
| - Async Event Dedupe         |
| - Learning State             |
+------------------------------+
   |           |            |
   v           v            v
Stick A     Stick B      Stick N
```

## Routing Modes

### smart (recommended)

- As long as a `primary_stick` is online, requests are sent only to that stick.
- During EZSP handshake (`RST`), requests are sent to all online sticks.
- The stick that returns a valid `RSTACK` becomes the `primary_stick`.
- On timeout/error, the proxy can fail over to another stick.

### broadcast

- Every request is sent to all online sticks.
- There is no `primary_stick` concept.
- For EZSP, the proxy waits for the first valid response.

## Logging

Logging is split into 5 categories. Each category has its own level in the `logging` section of `config.yaml`.

Available levels:

- `debug`
- `info`
- `warning`
- `error`
- `critical`

Categories:

- `startup`: start/stop, connections, client lifecycle
- `healthcheck`: periodic overall status logs
- `traffic`: RX/TX, frame flow, routing attempts
- `statistics`: timeout/retry/failover/success metrics
- `learning`: load/save/update of learning state

### Important About `hex_dump`

`hex_dump` is **no longer configurable**.

Hex dumps are always emitted through the `traffic` category at `DEBUG`.
This means: as soon as `logging.traffic: debug` is set, hex dumps are shown by default.

## Configuration

File: [data/config.yaml](data/config.yaml)

```yaml
proxy:
  listen_host: 0.0.0.0
  listen_port: 6638

sticks:
  - name: stick1
    host: 192.168.1.100
    port: 6638
  - name: stick2
    host: 192.168.1.101
    port: 6638

retry:
  max_attempts: 3
  delay_seconds: 2

timeout:
  response_timeout: 5

routing: # smart | broadcast
  mode: smart

learning:
  ttl_seconds: 3600

logging: # debug, info, warning, error
  startup: info
  healthcheck: warning
  traffic: info
  statistics: info
  learning: info
```

Notes:

- `routing.mode` only accepts `smart` or `broadcast`.
- `learning.ttl_seconds` must be >= 1.
- Invalid values fall back to safe defaults.

## Learning-State

File: `learning_state.json`

- Loaded on startup.
- Updated in memory.
- Persisted on clean shutdown.
- Old/expired entries are cleaned up based on TTL.

Example:

```json
{
  "0011223344556677:89abcdef01": {
    "stick1": {
      "count": 12,
      "timestamp": 1710000000.123
    }
  }
}
```

## Local Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 proxy.py --data ./data
```

## Docker

```bash
docker compose up -d --build
docker compose logs -f zmsp
```

On startup:

- If `/data/config.yaml` is missing, `/app/data/config.yaml` is copied.
- If `/data/learning_state.json` is missing, the file is created.

## Zigbee2MQTT Example

```yaml
serial:
  port: tcp://192.168.0.100:6638
  adapter: ember # or ezsp/zstack depending on your coordinator
  baudrate: 115200
  rtscts: false
```

## Troubleshooting

### No Sticks Online

- Check reachability of stick IPs and port 6638.
- Check firewall/ACL rules between proxy and stick network.

### Frequent Timeouts

- Increase `timeout.response_timeout` (for example, 7-10 seconds).
- Adjust `retry.max_attempts` and `retry.delay_seconds`.
- Improve network stability (Ethernet preferred when possible).

### Too Many Logs

- Raise category levels individually, for example:
  - `traffic: info`
  - `healthcheck: warning`

### Second Z2M Client Is Rejected

- Expected behavior: exactly one concurrent Z2M client is allowed.

## Operational Notes

- The proxy is designed for LAN operation.
- In segmented networks, apply ACL/firewall rules.
- Logs may contain diagnostic/traffic details; secure access accordingly.
