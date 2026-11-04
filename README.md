# NTN Dongle Test

Python scripts for testing and controlling NTN (Non-Terrestrial Network) modems with integrated LoRa modules over Modbus RTU.

## Scripts

| File | Purpose |
|------|---------|
| `ntn_modbus_master_sample.py` | Main script — NIDD/UDP testing, uplink/downlink, LoRa provisioning, UDP device config, nRF9151 commands |

nRF9151 firmware reference docs are in `doc/`: `NTN_STATUS_SPEC.md` (status query commands), `LEO_VERSION_OPERATION.md`, `GEO_VERSION_OPERATION.md`, and the Nordic `nrf91x1_ntn_at_commands_v1.2.pdf`.

## Features

- Reads device info: Serial Number, Model Name, Firmware/Hardware versions, Modbus ID, Heartbeat
- Retrieves NTN metrics: IMSI, SINR, RSRP, GPS Latitude/Longitude
- Monitors NTN module status (AT ready, SIM ready, network registered, socket ready)
- Logs upload availability, RSRP/SINR and GPS Latitude/Longitude every status loop iteration
- Supports NIDD and UDP protocol modes
- Configures UDP network parameters (remote IP, port, APN, local port) via `--ntn_config`
- Optional downlink data reading in a separate thread
- Optional uplink data transmission (signal metrics, GPS, and/or a UAV MAVLink-telemetry sample) with configurable packet types
- LoRa co-module (A2 hardware) key provisioning (ABP private keys + OTAA EUI) and AT command passthrough
- Sets the dongle's CSQ/GPS read interval (`--csq_gps_interval`, saved to EEPROM)
- NTN/TN module command channel — **only supported on the Nordic nRF9151 modem**:
  - LEO satellite config from a TLE file or fetched live from CelesTrak (`--leo_config` + `--tle_file` / `--tle_norad` / `--tle_name`)
  - Network mode triggers (`--ntn_trigger`), registration status (`--network_registration_status`)
  - Status queries (`--ntn_query`: `NSTATE`, `NCHECK`, `NGNSS`, `NEXTPASS`, `SIB32`, …)
  - LEO auto-MO queue management (`--mobuf`, `--mobuf_clear`, `--mocount`)
- Configurable status loop interval via `--interval`
- Thread-safe Modbus communication using a port lock

## Prerequisites

- Python 3.6+
- `modbus_tk==1.1.5`
- `pyserial==3.5`
- NTN Modbus device connected via serial port (e.g., `/dev/ttyUSB0`)

## Installation

```bash
git clone https://github.com/CREATIVE5-io/Hestia-sample-Python.git
cd Hestia-sample-Python
pip install -r requirements.txt
```

## Usage

```bash
python ntn_modbus_master_sample.py [options]
```

### General options

| Argument | Description | Default |
|----------|-------------|---------|
| `--type` | Protocol mode: `NIDD` or `UDP` | `UDP` |
| `--port` | Serial port | `/dev/ttyUSB0` |
| `--upload` | Enable uplink data transmission | `False` |
| `--ud_type` | Upload data type: `signal`, `gps`, `uav`, or `all` (`all` = signal+gps; `uav` must be selected explicitly) | `all` |
| `--ud_data` | Raw upload data string sent as-is; overrides `--ud_type`, implies `--upload` | `None` |
| `--uav_data` | JSON object overriding individual `uav` fields; unspecified fields use sample defaults | `None` |
| `--ud_size` | Pad upload payload to this many bytes with repeating `1234567890` fill (`0` = no padding) | `0` |
| `--ud_fill` | Send exactly `--ud_size` bytes of repeating `1234567890`, no other data; implies `--upload` (uses `150` if `--ud_size` is `0`) | `False` |
| `--no_ack` | Skip waiting on `0xF060`/`0xF061` after upload, for dongle firmware that never sends an uplink ACK (older firmware only — the wait loop blocks forever otherwise) | `False` |
| `--ceresgate` | CeresGate UDP gateway format: dongle FW version must start with `E` (else exits with `'--ceresgate' not supported`) and `--type UDP`. Uplinks become `hex(IMSI + data)` (15-digit IMSI from `0xEB00`, compact JSON, warns over 256 B); downlinks are hex-decoded and repeats flagged. Register/log in at https://ceresgate.aiotxems.io for the gateway IP/port and write them with `--ntn_config` first | `False` |
| `--dl` | Enable downlink reading in a separate thread | `False` |
| `--interval` | Status loop interval in seconds | `600` |
| `--log_file` | Log file path; set to `''` to disable file logging | `ntn_modbus.log` |
| `--csq_gps_interval` | One-shot: set how often the dongle reads CSQ/GPS from the NTN module (holding reg `0xC35B`, saved to EEPROM), read it back, then exit. `off`, `1`/`10`/`30`/`60` (minutes), `default` (original ~0.9 s cycle), or `get` (read only) | `None` |

Run `python ntn_modbus_master_sample.py --help` for the options grouped by hardware (common / nRF9151 / LoRa) plus examples.

### UDP device config options

Used with `--ntn_config` to write network parameters to the device (one-shot, exits after writing).

| Argument | Description | Default |
|----------|-------------|---------|
| `--ntn_config` | Enable UDP config mode | `False` |
| `--remote_port` | Remote server port | `''` |
| `--apn` | APN string | `''` |
| `--ip` | Remote server IP address | `''` |
| `--local_port` | Local port (optional) | `''` (defaults to `55001` if omitted) |

### NTN/TN module command options (0x9C40)

> **Nordic nRF9151 modem only.** All options in this section talk to the `0x9C40` module command channel introduced by the Nordic nRF9151 modem firmware; they are not supported on other dongle modems. Replies come back on `0xF060`/`0xF061` (shared with the uplink ACK).

`--network_registration_status` and `--ntn_query ... --ntn_query_once` run and exit. `--leo_config`, `--ntn_trigger`, `--mobuf_clear`, `--mobuf` and `--mocount` run once and then continue into the normal status loop (or into `--ntn_query_once`, so the queue can be verified in the same run).

| Argument | Description | Default |
|----------|-------------|---------|
| `--network_registration_status` | Query network registration status (`AT+CEREG?`), log the reply, then exit | `False` |
| `--leo_config` | Configure LEO target satellite (`SET_TARGET_ID`) and orbit (`SET_TLE`); requires exactly one of `--tle_file`, `--tle_norad`, `--tle_name` | `False` |
| `--tle_file` | 3-line TLE file for `--leo_config`: line 1 is the satellite name (only `SATELIOT_<id>` is supported; the target ID is parsed from it), lines 2–3 are the TLE | `None` |
| `--tle_norad` | Fetch the name + current TLE from [CelesTrak](https://celestrak.org/) by NORAD catalog number (e.g. `60534` = `SATELIOT_2`); needs internet | `None` |
| `--tle_name` | Fetch the current TLE from CelesTrak by exact satellite name (e.g. `SATELIOT_2`); needs internet | `None` |
| `--ntn_trigger` | Trigger network mode: `sgp4` (LEO tracking), `gnss` (GNSS fix), `tn` (terrestrial), `ntn` (GEO satellite) | `None` |
| `--ntn_query` | Status query command(s), case-insensitive: `NSTATE`, `NCHECK`, `NGNSS`, `NSIGNAL`, `NREG`, `NMO`, `NTLE`, `NCFG`, `NVER`, `NERR`, `NEXTPASS` (next LEO pass: AOS/TCA/LOS/max elevation), `MOBUF` (auto-MO queue depth), `SIB32` (latest raw SIB32 ephemeris), or `ALL`. Sent each status loop iteration before uplink; raw and parsed replies are logged | `None` |
| `--ntn_query_once` | With `--ntn_query`: run the queries once (skipping the device setup flow) and exit | `False` |
| `--mobuf_clear` | Clear the LEO auto-MO queue (bare `MOBUF`); runs before `--mobuf` | `False` |
| `--mobuf` | Append payload(s) to the auto-MO queue (`MOBUF <text>`, NVS-persisted, sent on each LEO pass) | `None` |
| `--mocount` | Auto-MO sends per pass (`MOCOUNT <N>`, `0`..`100`, `0` = firmware default 5) | `None` |

`--ntn_query` fields follow `doc/NTN_STATUS_SPEC.md` §3; `NCHECK`'s bitmap is also expanded into named flags (`module_ready`, `sim_ready`, `provider_resolved`, `gnss_fix_valid`, `tle_valid`, `ntn_registered`, `socket_open`, `mo_queue_pending`).

**Getting TLE data:** use `--tle_norad` / `--tle_name` to fetch the current TLE from CelesTrak automatically. For `--tle_file`, [n2yo.com](https://www.n2yo.com/) or CelesTrak provide up-to-date TLE data — copy the two TLE lines into the file (line 1 must be named `SATELIOT_<id>` for `parse_tle_file()` to accept it).

**NTN trigger workflow:** before triggering `ntn` (GEO), first trigger `gnss` and confirm the device has an updated GPS fix — check Latitude/Longitude (`0xEB1B`/`0xEB20`, logged at startup by `ntn_info()` and every status loop iteration, or uploaded via `--ud_type gps`) has actually changed/updated — then trigger `ntn`.

### LoRa options (A2 hardware)

Require `lora.ini` in the same directory. Auto-created with defaults if missing.

| Argument | Description | Default |
|----------|-------------|---------|
| `--lora` | Enable LoRa data polling in the status loop | `False` |
| `--lora_setup` | Configure LoRa module (frequency, SF, channel plan) | `False` |
| `--lora_node_query` | Query all 16 LoRa node key slots (private keys + OTAA EUI) | `False` |
| `--lora_node_setup` | Write private keys and OTAA EUI from `lora.ini` to device | `False` |
| `--lora_node_cleanup` | Wipe all 16 private key slots and OTAA EUI entries | `False` |
| `--lora_pubkey_setup` | Write public key from `lora.ini` to device | `False` |
| `--lora_pubkey_cleanup` | Wipe public key | `False` |

### UAV Uplink Payload (`--ud_type uav`)

The dongle has no direct MAVLink connection, so `uav` sends a MAVLink-derived telemetry sample rather than live-read register data (unlike `signal`/`gps`). Field values default to a fixed example set; `ts_unix_s` is always recomputed to the current time unless overridden via `--uav_data`.

| idx | field | unit | default | note |
|---|---|---|---|---|
| 0 | `"uav"` | — | `"uav"` | fixed type tag |
| 1 | `ts_unix_s` | s | current time | UNIX seconds; override via `--uav_data '{"ts_unix_s": ...}'` |
| 2 | `mode_id` | enum | `5` | flight mode |
| 3 | `landed_state` | enum | `2` | landed/in-air state |
| 4 | `system_status` | enum | `4` | system status |
| 5 | `lat_e7` | degE7 | `231067201` | latitude |
| 6 | `lon_e7` | degE7 | `1202108074` | longitude |
| 7 | `rel_alt_dm` | dm | `199` | relative altitude |
| 8 | `heading_deg10` | 0.1° | `629` | heading |
| 9 | `gspeed_dms` | 0.1 m/s | `10` | ground speed |
| 10 | `bat_voltage_cV` | 0.01V | `1418` | battery voltage |
| 11 | `bat_current_cA` | 0.01A | `865` | battery current |
| 12 | `gps_fix_type` | enum | `4` | GPS fix type |
| 13 | `mission_pct` | % | `56` | mission progress; `255` = invalid |

Default payload:
```json
{"D":[{"mv":["uav",1776657541,5,2,4,231067201,1202108074,199,629,10,1418,865,4,56]}]}
```

Use `--uav_data` to override any subset of fields by name (indices 2–13, plus `ts_unix_s`); unlisted fields keep their default.

### Examples

```bash
# UDP mode with uplink (signal + GPS) and downlink, 30-second polling
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl --interval 30

# Send a fixed raw string as uplink payload (bypasses --ud_type)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ud_data '{"c":[42,-80]}'

# NIDD mode, upload signal data only
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --type NIDD --upload --ud_type signal

# Send the default UAV telemetry sample payload
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --ud_type uav

# Override specific uav fields, keep the rest as sample defaults
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --ud_type uav \
    --uav_data '{"mode_id":3,"lat_e7":231067300,"mission_pct":80}'

# Configure UDP network parameters (one-shot)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_config \
    --remote_port 55001 --apn my.apn.example --ip 1.2.3.4 --local_port 55002

# LoRa key setup from lora.ini (private keys + OTAA EUI + public key)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --lora_setup --lora_node_setup --lora_pubkey_setup

# Query all 16 LoRa node key slots (private keys + OTAA EUI)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --lora_node_query

# Pad every upload payload out to 150 bytes for consistent-size testing
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --ud_type signal --ud_size 150

# Send exactly 150 bytes of repeating filler, no JSON payload
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ud_fill --ud_size 150

# Upload on firmware that never sends an uplink ACK
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --ud_type signal --no_ack

# Run without writing to a log file
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --log_file ''

# Query network registration status (Nordic nRF9151 modem only)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --network_registration_status

# Set the CSQ/GPS read interval to 10 min, or read the current value back
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --csq_gps_interval 10
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --csq_gps_interval get

# Configure LEO target satellite + orbit from a 3-line TLE file, then start LEO tracking (Nordic nRF9151 modem only)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --leo_config --tle_file tle.txt --ntn_trigger sgp4

# Same, but fetch the current TLE from CelesTrak by NORAD catalog number or exact name
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --leo_config --tle_norad 60534 --ntn_trigger sgp4
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --leo_config --tle_name SATELIOT_2 --ntn_trigger sgp4

# Query nRF9151 status every status loop iteration (every 30 s)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_query nstate ncheck ngnss --interval 30

# Run all status queries once and exit
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_query all --ntn_query_once

# Query the next predicted LEO pass once
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_query nextpass --ntn_query_once

# Reload the auto-MO queue, send each payload 10x per pass, then verify queue depth / MO count and dump SIB32
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --mobuf_clear --mobuf hello world --mocount 10 \
    --ntn_query mobuf nmo sib32 --ntn_query_once

# Trigger LEO / terrestrial network mode (Nordic nRF9151 modem only)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_trigger sgp4   # LEO
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_trigger tn     # terrestrial

# Trigger GEO (ntn): first trigger gnss and confirm GPS location has updated, then trigger ntn
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_trigger gnss   # confirm Latitude/Longitude updates before continuing
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_trigger ntn    # GEO
```

## LoRa Configuration (`lora.ini`)

Auto-created with defaults on first run. Edit before running LoRa key operations.

```ini
[LORA]
frequency = 923200000
sf = 9
ch_plan = 0   # 0=AS923, 1=US915, 2=AU915, 3=EU868, 4=KR920, 5=IN865, 6=RU864

[PRIVATE_KEY]
# ABP keys: <name> = <slot>:<devaddr>:<nwkskey>:<appskey>
device1 = 0:<devaddr>:<nwkskey>:<appskey>
device2 = 1:<devaddr>:<nwkskey>:<appskey>

[OTAA_EUI]
# OTAA keys (requires LoRa FW >= V1.3.0): <name> = <slot>:<DevEUI>:<AppEUI>:<AppKey>
device1 = 0:<DevEUI>:<AppEUI>:<AppKey>

[PUBLIC_KEY]
pubkey = <hex_key>:<hex_key>
```

## Status Register (`0xEA71`) Bit Flags

| Mode | Ready condition |
|------|----------------|
| NIDD | bits 0–3 all set (`0x0F`): AT ready, downlink ready, SIM ready, network registered |
| UDP  | bits 0–4 all set (`0x1F`): same as NIDD plus socket ready |

## Key Modbus Register Map

| Address | R/W | Purpose |
|---------|-----|---------|
| `0x0000` | W | Password (4×u16, default `00000000`) |
| `0xEA60–0xEA65` | R | Serial number |
| `0xEA66–0xEA6A` | R | Model name |
| `0xEA6B–0xEA6C` | R | FW version |
| `0xEA6D–0xEA6E` | R | HW version |
| `0xEA6F` | R | Modbus ID |
| `0xEA70` | R | Heartbeat |
| `0xEA71` | R | Status flags |
| `0xEA7D` | R | Uplink buffer available (0 = ready) |
| `0xEB00–0xEB07` | R | IMSI |
| `0xEB13–0xEB14` | R | SINR |
| `0xEB15–0xEB16` | R | RSRP |
| `0xEB1B–0xEB1F` | R | Latitude |
| `0xEB20–0xEB25` | R | Longitude |
| `0xC35B` | R/W | CSQ/GPS read interval (holding, EEPROM): `0`=off, `1`/`2`/`3`/`4`=1/10/30/60 min, `0xFE`=~0.9 s default |
| `0xC3B8` | R/W | UDP remote port |
| `0xC3BB` | R/W | UDP APN name |
| `0xC3CA` | R/W | UDP remote IP |
| `0xC3D5` | R/W | UDP local port |
| `0xC550` | W | Uplink data write |
| `0xC700+` | W | LoRa AT command write |
| `0x9C40` | W | NTN/TN module command channel (ASCII + CRLF; CEREG/SET_TARGET_ID/SET_TLE/triggers/status queries/MOBUF/MOCOUNT — **Nordic nRF9151 modem only**) |
| `0xEC60` | R | Downlink data length |
| `0xEC61+` | R | Downlink data |
| `0xF060` | R | Uplink response length (also used for 0x9C40 NTN/TN command replies) |
| `0xF061+` | R | Uplink response data (also used for 0x9C40 NTN/TN command replies) |
| `0xF460` | R | `AT+BISGET=?` response length |
| `0xF461+` | R | `AT+BISGET=?` response data |
| `0xF860` | R | General AT response length |
| `0xF861+` | R | General AT response data |

## Troubleshooting

- Verify the serial port is accessible and the device is powered on
- Default Modbus slave ID is 1; default password is `00000000`
- Increase `self.master.set_timeout` in the source if communication errors occur
- Check status log output to confirm the device reaches ready state before uplink/downlink
- After `--ntn_config`, unplug and replug the dongle to apply new network settings

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for suggestions or bug reports.
