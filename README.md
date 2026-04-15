# NTN Dongle Test

Python scripts for testing and controlling NTN (Non-Terrestrial Network) modems with integrated LoRa modules over Modbus RTU.

## Scripts

| File | Purpose |
|------|---------|
| `ntn_modbus_master_sample.py` | Main script — NIDD/UDP testing, uplink/downlink, LoRa provisioning, UDP device config |
| `ntn_modbus_to_atCmd.py` | Standalone AT command passthrough utility |

## Features

- Reads device info: Serial Number, Model Name, Firmware/Hardware versions, Modbus ID, Heartbeat
- Retrieves NTN metrics: IMSI, SINR, RSRP, GPS Latitude/Longitude
- Monitors NTN module status (AT ready, SIM ready, network registered, socket ready)
- Supports NIDD and UDP protocol modes
- Configures UDP network parameters (remote IP, port, APN, local port) via `--ntn_config`
- Optional downlink data reading in a separate thread
- Optional uplink data transmission (signal metrics and/or GPS) with configurable packet types
- LoRa co-module (A2 hardware) key provisioning and AT command passthrough
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
| `--ud_type` | Upload data type: `signal`, `gps`, or `all` | `all` |
| `--dl` | Enable downlink reading in a separate thread | `False` |
| `--interval` | Status loop interval in seconds | `600` |

### UDP device config options

Used with `--ntn_config` to write network parameters to the device (one-shot, exits after writing).

| Argument | Description | Default |
|----------|-------------|---------|
| `--ntn_config` | Enable UDP config mode | `False` |
| `--remote_port` | Remote server port | `''` |
| `--apn` | APN string | `''` |
| `--ip` | Remote server IP address | `''` |
| `--local_port` | Local port (optional) | `55001` |

### LoRa options (A2 hardware)

Require `lora.ini` in the same directory. Auto-created with defaults if missing.

| Argument | Description | Default |
|----------|-------------|---------|
| `--lora` | Enable LoRa data polling in the status loop | `False` |
| `--lora_setup` | Configure LoRa module (frequency, SF, channel plan) | `False` |
| `--lora_privkey_query` | Query LoRa private key slot 0 | `False` |
| `--lora_privkey_setup` | Write private keys from `lora.ini` to device | `False` |
| `--lora_privkey_cleanup` | Wipe all 16 private key slots | `False` |
| `--lora_pubkey_setup` | Write public key from `lora.ini` to device | `False` |
| `--lora_pubkey_cleanup` | Wipe public key | `False` |

### Examples

```bash
# UDP mode with uplink (signal + GPS) and downlink, 30-second polling
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl --interval 30

# NIDD mode, upload signal data only
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --type NIDD --upload --ud_type signal

# Configure UDP network parameters (one-shot)
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --ntn_config \
    --remote_port 55001 --apn my.apn.example --ip 1.2.3.4 --local_port 55002

# LoRa key setup from lora.ini
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --lora_setup --lora_privkey_setup --lora_pubkey_setup

# Query LoRa private key slot 0
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --lora_privkey_query

# Raw AT command passthrough (no full device setup flow)
python ntn_modbus_to_atCmd.py --port /dev/ttyUSB0
```

## LoRa Configuration (`lora.ini`)

Auto-created with defaults on first run. Edit before running LoRa key operations.

```ini
[LORA]
frequency = 923200000
sf = 9
ch_plan = 0   # 0=AS923, 1=US915, 2=AU915, 3=EU868, 4=KR920, 5=IN865, 6=RU864

[PRIVATE_KEY]
device1 = 0:<devaddr>:<nwkskey>:<appskey>
device2 = 1:<devaddr>:<nwkskey>:<appskey>

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
| `0xC3B8` | R/W | UDP remote port |
| `0xC3BB` | R/W | UDP APN name |
| `0xC3CA` | R/W | UDP remote IP |
| `0xC3D5` | R/W | UDP local port |
| `0xC550` | W | Uplink data write |
| `0xC700+` | W | LoRa AT command write |
| `0xEC60` | R | Downlink data length |
| `0xEC61+` | R | Downlink data |
| `0xF060` | R | Uplink response length |
| `0xF061+` | R | Uplink response data |
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
