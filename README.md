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
  - `modbus_tk`
  - `pyserial`
- A compatible NTN Modbus Master device connected via a serial port (e.g., `/dev/ttyUSB0`).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/CREATIVE5-io/Hestia-sample-Python.git
   cd Hestia-sample-Python
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the script with optional command-line arguments:

```bash
python ntn_modbus_master_sample.py [--port <serial_port>] [--upload] [--dl]
```


### Arguments
- `--type`: Protocol to use on NTN service (default: `NIDD`).
- `--port`: Serial port of the device (default: `/dev/ttyUSB0`).
- `--upload`: Enable periodic uplink data transmission (optional).
- `--dl`: Enable continuous downlink data reading in a separate thread (optional).
- `--lora_setup`: Enable LoRa module setup (optional).
- `--lora_privkey_query`: Query LoRa private keys (optional).
- `--lora_privkey_setup`: Setup LoRa private keys from lora.ini (optional).
- `--lora_privkey_cleanup`: Cleanup all LoRa private keys (optional).
- `--lora_pubkey_setup`: Setup LoRa public key from lora.ini (optional).
- `--lora_pubkey_cleanup`: Cleanup LoRa public key (optional).


### Example
```bash
# Basic usage
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl

# LoRa device setup from lora.ini
python ntn_modbus_master_sample.py --lora_setup --lora_privkey_setup --lora_pubkey_setup

# Query LoRa private keys
python ntn_modbus_master_sample.py --lora_privkey_query
```

## LoRa Device Configuration

The script supports LoRa device configuration using a `lora.ini` file in the same directory. This file should contain device and key information in INI format.

### Example lora.ini
```ini
[LORA]
frequency = 923200000
sf = 9
ch_plan = 0

[PRIVATE_KEY]
device1 = 0:002f2ebb:2b7e151628aed2a6abf7158809cf4f3c:2b7e151628aed2a6abf7158809cf4f3c
device2 = 1:003040c7:2b7e151628aed2a6abf7158809cf4f3c:2b7e151628aed2a6abf7158809cf4f3c

[PUBLIC_KEY]
pubkey = ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff
```

### How it works
- The script reads the `[DEVICES]` section from `lora.ini` and uses these values for LoRa private key setup if `--lora_privkey_setup` is specified.
- The `[LORA]` section is used for LoRa module setup if `--lora_setup` is specified.
- Public key setup uses the `[PUBLIC_KEY]` section if present.

### LoRa-related Arguments
- `--lora_setup`: Setup LoRa module parameters (frequency, SF, channel plan) from `[LORA]` section.
- `--lora_privkey_setup`: Setup LoRa private keys from `[DEVICES]` section.
- `--lora_privkey_query`: Query LoRa private keys from the device.
- `--lora_privkey_cleanup`: Cleanup all LoRa private keys on the device.
- `--lora_pubkey_setup`: Setup LoRa public key from `[PUBLIC_KEY]` section.
- `--lora_pubkey_cleanup`: Cleanup LoRa public key on the device.


## Script Overview
The script:
1. Parses command-line arguments for port, uplink, downlink, and LoRa options.
2. Initializes a Modbus RTU master connection with the specified port and slave address (default: 1).
3. Sets a default password (`00000000`) for device access.
4. Reads and logs device information (Serial Number, Model Name, Firmware/Hardware Versions, Modbus ID, Heartbeat).
5. Retrieves and logs NTN-specific data (IMSI, SINR, RSRP, GPS coordinates).
6. Reads LoRa device and key information from `lora.ini` if LoRa options are enabled.
7. Supports LoRa module setup, private/public key setup, cleanup, and query via command-line arguments.
8. Continuously checks NTN module status until fully ready (AT, SIM, network registered).
9. If `--dl` is enabled, starts a thread to monitor and log downlink data.
10. If `--upload` is enabled, periodically sends uplink data (SINR, RSRP) every 10 minutes and logs responses.
11. Uses a threading lock to ensure thread-safe Modbus communication.

## Logging
- Logs are output to the console with levels `INFO`, `DEBUG`, and `ERROR`.
- Includes detailed information about Modbus transactions, data conversions, and errors.

## Troubleshooting
- Ensure the serial port is correct and accessible.
- Verify the device is powered on and configured with the correct Modbus ID (default: 1).
- Check that dependencies (`modbus_tk`, `pyserial`) are installed.
- If downlink or uplink operations fail, confirm the device is in a ready state (use status logs).
- Increase the Modbus timeout (`self.master.set_timeout`) if communication errors occur.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for suggestions or bug reports.
