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
   pip install modbus_tk pyserial
   ```

## Usage
Run the script with optional command-line arguments:

```bash
python ntn_modbus_master_sample.py [--port <serial_port>] [--upload] [--dl]
```

### Arguments
- `--port`: Serial port of the device (default: `/dev/ttyUSB0`).
- `--upload`: Enable periodic uplink data transmission (optional).
- `--dl`: Enable continuous downlink data reading in a separate thread (optional).

### Example
```bash
python ntn_modbus_master_sample.py --port /dev/ttyUSB0 --upload --dl
```

## Script Overview
The script:
1. Parses command-line arguments for port, uplink, and downlink options.
2. Initializes a Modbus RTU master connection with the specified port and slave address (default: 1).
3. Sets a default password (`00000000`) for device access.
4. Reads and logs device information (Serial Number, Model Name, Firmware/Hardware Versions, Modbus ID, Heartbeat).
5. Retrieves and logs NTN-specific data (IMSI, SINR, RSRP, GPS coordinates).
6. Continuously checks NTN module status until fully ready (AT, SIM, network registered).
7. If `--dl` is enabled, starts a thread to monitor and log downlink data.
8. If `--upload` is enabled, periodically sends uplink data (SINR, RSRP) every 10 minutes and logs responses.
9. Uses a threading lock to ensure thread-safe Modbus communication.

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
