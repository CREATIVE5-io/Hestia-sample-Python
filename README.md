# NTN Dongle Test

This Python script is designed to test and interact with an NTN Modbus Master device over a serial connection using the Modbus RTU protocol. It provides functionality to read device information, monitor status, and perform uplink/downlink data operations.

## Features
- Reads device details such as Serial Number, Model Name, Firmware Version, Hardware Version, Modbus ID, and Heartbeat.
- Retrieves NTN-specific data like IMSI, SINR, RSRP, GPS Latitude, and Longitude.
- Monitors NTN module status (AT readiness, SIM status, network registration, etc.).
- Supports optional downlink data reading via a separate thread.
- Supports optional uplink data transmission with periodic reporting (e.g., SINR, RSRP).
- Thread-safe Modbus communication using a port lock.
- Detailed console logging for debugging and monitoring.

## Prerequisites
- Python 3.6+
- Required Python packages:
## Hestia-sample-Python

Tools and small example scripts to interact with an NTN dongle (Modbus RTU) using a serial port.

This repository contains two related scripts:

- `ntn_modbus_master_sample.py` — the main sample script that initializes a Modbus RTU master, reads device info, monitors status, optionally starts a downlink reader thread, and can periodically upload telemetry.

Both scripts use `modbus_tk` + `pyserial` to communicate with an NTN Modbus device.

## Prerequisites

- Python 3.6+
- Install dependencies from `requirements.txt`:

# Hestia-sample-Python

Tools and small example scripts to interact with an NTN dongle (Modbus RTU) using a serial port.

This repository contains two related scripts:

- `ntn_modbus_master_sample.py` — the main sample script that initializes a Modbus RTU master, reads device info, monitors status, optionally starts a downlink reader thread, and can periodically upload telemetry.
- `arg_test.py` — a smaller/testing script that exposes the same core functionality but is used for quick CLI-driven configuration and tests.

Both scripts use `modbus_tk` + `pyserial` to communicate with an NTN Modbus device.

## Prerequisites

- Python 3.6+
- Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

The current requirements file pins the primary dependencies:

```
modbus_tk==1.1.5
pyserial==3.5
```

## Quick start

1. Connect your NTN dongle to the host (e.g. via USB-to-serial). Note the serial device path (for macOS/Linux commonly `/dev/ttyUSB0` or `/dev/tty.usbserial-*`).
2. Run the main script:

```bash
python ntn_modbus_master_sample.py --port /dev/ttyUSB0
```

Add `--dl` to enable continuous downlink monitoring (runs a reader thread) and `--upload` to enable periodic uplink telemetry reporting.

## Command-line options

Both scripts expose similar CLI arguments. The important flags are:

- `--port`: Serial port device to open (default: `/dev/ttyUSB0`).
- `--ntn_config`: When provided, the script will configure the NTN dongle using values supplied via `--remote_port`, `--apn`, `--ip`, and optional `--local_port`.
- `--remote_port`: Remote port to set on the device (string).
- `--apn`: APN string to configure on the device.
- `--ip`: Remote IP address to set on the device.
- `--local_port`: Optional local port (defaults to `55001` in code if omitted).
- `--upload`: Enable periodic uplink (collects SINR/RSRP and sends over the device link).
- `--dl`: Start a background thread that continuously polls for downlink data and logs it.

Example: configure the device (requires the dongle to be connected):

```bash
python arg_test.py --ntn_config --remote_port 55001 --apn my.apn.example --ip 1.2.3.4 --local_port 55002 --port /dev/ttyUSB0
```

Example: start monitoring with both upload and downlink:

```bash
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl
```

## Behavior notes

- Default Modbus slave address used by the code is `1` (NTN_DONGLE_ADDR = 1).
- Serial parameters used when opening the port are 115200 baud, 8 data bits, no parity, 1 stop bit (8N1). Timeout is set via `self.master.set_timeout(1)` in code and can be adjusted in the source.
- The `ntn_config` function writes the remote port, APN, IP, and local port into specific Modbus registers. It expects a live `ntn_modbus_master` instance (the device connection) as the first parameter.
- After successful `--ntn_config` run, the sample script logs a success message and suggests unplugging/replugging the dongle to apply settings.

## Logging

- The scripts use `modbus_tk`'s console logger. The logger outputs INFO/DEBUG/ERROR messages to the console for troubleshooting and verification of the operations.

## Troubleshooting

- Permission denied when opening `/dev/ttyUSB0`? Add your user to the appropriate group or use `sudo` (prefer configuring udev/permissions instead of running as root).
- If Modbus reads/writes return `None` or empty values, check the device power, wiring, and Modbus ID. The code treats all-zero register responses as empty/invalid.
- Install dependencies explicitly if needed: `pip install modbus_tk pyserial`.

## Development notes & next steps

- The CLI currently supports both a single multi-argument option (`--ntn_config` + separate flags) and a test mode in `arg_test.py`. For clearer automation you may prefer separate flags (`--remote-port`, `--apn`, etc.) — these are already present in the code.
- Consider adding unit tests around data-conversion helpers such as `string_to_ascii_list` and `bytes_to_list_with_padding`.

## License

MIT

## Contributing

Raise issues or pull requests on the repository. Small, focused changes (tests, docs, bugfixes) are easiest to review.
