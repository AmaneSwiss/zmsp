# Zigbee Multi-Stick Proxy (Python)

A TCP proxy for Zigbee2MQTT that accepts exactly one Z2M client and forwards requests to multiple SLZB sticks.

The implementation supports two routing modes:
- smart (recommended)
- broadcast

##

### Architecture

```text
   Zigbee2MQTT (1 client)
              |
              v
+-----------------------------+
|      Proxy (Port 6638)      |
|                             |
| - Request queue             |
| - Retry/timeout             |
| - Frame validation          |
| - Smart failover            |
| - Health checks + KPIs      |
| - Passive learning + TTL    |
+-----------------------------+
   |           |           |
   v           v           v
 Stick A    Stick B     Stick N
```

### Core Logic

1. Z2M sends a frame to the proxy.
2. The proxy puts the frame into a queue (serial processing).
3. Target sticks are selected based on `routing.mode`.
4. The proxy waits for the first valid response.
5. Invalid or error frames are discarded.
6. On timeout/error, retry and optional failover are performed.

Important: ACK/NAK frames are only forwarded; no response is expected for them.

### Routing Behavior

#### smart

- If `primary_stick` is already set and online: the request is sent only to that stick.
- If `primary_stick` is not set and the request is an ASH-RST: broadcast to all online sticks.
- If a valid RSTACK is received for the RST, the responding stick becomes `primary_stick`.
- If no primary exists and the request is not RST: fallback to the first online stick and set it as `primary_stick`.
- On timeout/error, failover to another online stick can occur.

#### broadcast

- Every request is sent to all online sticks.
- No primary concept is used.

### Frame Validation

- ZNP: SOF/FCS/length checks.
- EZSP/ASH: delimiter, unescape, CRC16 checks, ACK/NAK heuristics.
- For EZSP and RST specifically: only RSTACK is accepted as a direct response.

### Features

- asyncio-based TCP communication
- Exactly one concurrent Z2M client
- Automatic stick reconnects
- Configurable retry/timeout
- Dedupe for asynchronous events (short time window)
- Health-check logging including KPIs
- Statistics about which stick delivered the winning response
- Passive learning with timestamp and TTL
- Graceful shutdown via SIGINT/SIGTERM

### Configuration

File: [config.yaml](data/config.yaml)

Supported keys:

```yaml
proxy:
  listen_host: 0.0.0.0
  listen_port: 6638

sticks:
  - name: stick1
    host: 192.168.1.101
    port: 6638
  - name: stick2
    host: 192.168.1.102
    port: 6638

retry:
  max_attempts: 3
  delay_seconds: 2

timeout:
  response_timeout: 5

routing:
  mode: smart # smart, broadcast

learning:
  ttl_seconds: 86400

logging:
  level: INFO # DEBUG, INFO, WARNING, ERROR
  hex_dump: false
```

Notes:
- `routing.mode` only accepts `smart` or `broadcast`.
- `learning.ttl_seconds` must be >= 1.
- If `learning.ttl_seconds` is invalid, it falls back to 86400 seconds.

### Passive Learning

The file `learning_state.json` is loaded, maintained in RAM, and written during clean shutdown.

Structure per request signature:

```json
{
  "<signature>": {
    "stick1": {
      "count": 12,
      "timestamp": 1710000000.123
    }
  }
}
```

Behavior:
- `count` is incremented for every winning valid response.
- `timestamp` is updated to current time on every update.
- Expired entries are removed according to `learning.ttl_seconds`.
Old format is migrated automatically when loading:
  - old: `"stick1": 3`
  - new: `"stick1": {"count": 3, "timestamp": <now>}`

### Installation (Local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 proxy.py --data ./data
```

CLI notes:
- Default for `--data` is `/data`.
- The proxy expects `config.yaml` in the data directory.
- The `learning_state.json` will be created if missing.

### Docker

```bash
docker compose up -d --build
docker compose logs -f zmsp
```

On startup:
- If `/data/config.yaml` is missing, `/app/data/config.yaml` is copied to `/data`.
- If `/data/learning_state.json` is missing, the file will be created.

### Usage with Zigbee2MQTT

```yaml
serial:
  port: tcp://192.168.0.100:6638
  adapter: ember # ember, ezsp, zstack - depending on the coordinator
  baudrate: 115200
  rtscts: false
```

If Zigbee2MQTT runs on the same Docker host, set the proxy IP/internal network accordingly.

### Troubleshooting

#### No Sticks Online

- Check reachability of stick IPs and port 6638.
- Check firewall/ACL rules between proxy host and stick network.

#### Frequent Timeouts

- Increase `timeout.response_timeout` (for example, 7-10 seconds).
- Adjust `retry.max_attempts` and `retry.delay_seconds`.
- Stabilize the network (Ethernet preferred).

#### Second Z2M Client Is Rejected

- This is expected behavior: only one Z2M client at a time.

#### Unexpected Asynchronous Events

- In `smart` mode, events from non-primary sticks are discarded when a primary is set.
- For analysis, set `logging.level` to `DEBUG` and optionally `hex_dump` to `true`.

#### Health-Check Connections

- Loopback connections are detected as health checks and are not registered as Z2M clients.

### Security / Operations

- Operation without TLS is intended for typical LAN setups.
- In segmented networks, ACL/firewall rules should be applied.
- Logs may contain diagnostic data; secure access accordingly.
