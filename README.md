# NTN Dongle Test

Python scripts for testing and controlling NTN (Non-Terrestrial Network) modems with integrated LoRa modules over Modbus RTU.

## Scripts

| File | Purpose |
|------|---------|
| `ntn_modbus_master_sample.py` | Main script — NIDD/UDP testing, uplink/downlink |

## Features

- Reads device info: Serial Number, Model Name, Firmware/Hardware versions, Modbus ID, Heartbeat
- Retrieves NTN metrics: IMSI, SINR, RSRP, GPS Latitude/Longitude
- Monitors NTN module status (AT ready, SIM ready, network registered, socket ready)
- Supports NIDD and UDP protocol modes
- Optional downlink data reading in a separate thread
- Optional uplink data transmission (signal metrics and/or GPS)
- LoRa key provisioning via AT command passthrough
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

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--type` | Protocol mode: `NIDD` or `UDP` | `UDP` |
| `--port` | Serial port | `/dev/ttyUSB0` |
| `--upload` | Enable uplink data transmission | `False` |
| `--ud_type` | Upload data type: `signal`, `gps`, or `all` | `all` |
| `--dl` | Enable downlink reading in a separate thread | `False` |

### Examples

```bash
# UDP mode with uplink (signal + GPS) and downlink
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl

# NIDD mode, upload signal data only
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --type NIDD --upload --ud_type signal

# Raw AT command passthrough
python ntn_modbus_to_atCmd.py --port /dev/ttyUSB0
```

## Status Register (`0xEA71`) Bit Flags

| Mode | Ready condition |
|------|----------------|
| NIDD | bits 0–3 all set (`0x0F`): AT ready, downlink ready, SIM ready, network registered |
| UDP  | bits 0–4 all set (`0x1F`): same as NIDD plus socket ready |

## Troubleshooting

- Verify the serial port is accessible and the device is powered on
- Default Modbus slave ID is 1; default password is `00000000`
- Increase `self.master.set_timeout` if communication errors occur
- Check status log output to confirm the device reaches ready state before uplink/downlink

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for suggestions or bug reports.
