# === Standard Library Imports ===
import argparse
import binascii
import configparser
import json
import logging
import os
import re
import struct
import sys
import threading
from time import sleep, time

# === Third-Party Imports ===
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_rtu as modbus_rtu
import serial

# === Argument Parsing ===
def parse_arguments():
    parser = argparse.ArgumentParser(description="NTN-MODBUS-MASTER-TEST")
    parser.add_argument("--type", type=str, help="Specify NIDD or UDP (default: UDP)", default='UDP')
    parser.add_argument("--port", type=str, help="Specify port (default: /dev/ttyUSB0)", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test (default: False)", default=False)
    parser.add_argument("--ud_type", type=str, choices=['signal', 'gps', 'all'], default='all',
                        help="Upload data type: 'signal' for RSRP/SINR, 'gps' for lat/long, 'all' for both (default: all)")
    parser.add_argument("--dl", action='store_true', help="Enable downlink test (default: False)", default=False)
    parser.add_argument("--interval", type=int, help="Status loop interval in seconds (default: 600)", default=600)
    # UDP device config
    parser.add_argument("--ntn_config", action='store_true', help="Configure NTN dongle UDP parameters, ONLY use this config in UDP version dongle firmware", default=False)
    parser.add_argument("--remote_port", type=str, help="Specify remote port", default='')
    parser.add_argument("--apn", type=str, help="Specify APN", default='')
    parser.add_argument("--ip", type=str, help="Specify remote IP", default='')
    parser.add_argument("--local_port", type=str, help="Specify local port", default='')
    # LoRa (A2 hardware)
    parser.add_argument("--lora", action='store_true', help="Enable LoRa data polling in status loop (default: False)", default=False)
    parser.add_argument("--lora_setup", action='store_true', help="Enable LoRa module setup", default=False)
    parser.add_argument("--lora_privkey_query", action='store_true', help="Query LoRa private keys", default=False)
    parser.add_argument("--lora_privkey_setup", action='store_true', help="Setup LoRa private keys from lora.ini", default=False)
    parser.add_argument("--lora_privkey_cleanup", action='store_true', help="Cleanup all LoRa private keys", default=False)
    parser.add_argument("--lora_pubkey_setup", action='store_true', help="Setup LoRa public key from lora.ini", default=False)
    parser.add_argument("--lora_pubkey_cleanup", action='store_true', help="Cleanup LoRa public key", default=False)
    return parser.parse_args()

# === Logger Setup ===
logger = modbus_tk.utils.create_logger('console')


class ntn_modbus_master:
    def __init__(self, slaveAddress, port, baudrate=115200, bytesize=8, parity='N', stopbits=1, xonxoff=0):
        try:
            self.master = modbus_rtu.RtuMaster(serial.Serial(port=port, baudrate=baudrate, bytesize=bytesize, parity=parity, stopbits=stopbits, xonxoff=xonxoff))
            self.master.set_timeout(1)
            self.master.set_verbose(False)
            self.slaveAddr = slaveAddress
            self.lock = threading.Lock()
            logger.info('NTN dongle init!')
        except modbus_tk.modbus.ModbusError as e:
            logger.error(f'{e} - Code={e.get_exception_code()}')
            raise

    def read_register(self, reg, functioncode=cst.READ_INPUT_REGISTERS):
        with self.lock:
            try:
                value = self.master.execute(self.slaveAddr, functioncode, reg, 1)
                return value[0]
            except Exception as e:
                logger.info(e)
                return None

    def read_registers(self, reg, num, functioncode=cst.READ_INPUT_REGISTERS):
        with self.lock:
            try:
                values = self.master.execute(self.slaveAddr, functioncode, reg, num)
                if all(x == 0 for x in values):
                    return None
                return values
            except Exception as e:
                logger.info(e)
                return None

    def set_registers(self, reg, val):
        with self.lock:
            try:
                if val is not None:
                    self.master.execute(self.slaveAddr, cst.WRITE_MULTIPLE_REGISTERS, reg, output_value=val)
                    return True
                else:
                    return False
            except Exception as e:
                logger.info(e)
                return False

    @staticmethod
    def modbus_data_to_string(modbus_data):
        try:
            byte_data = b''.join(struct.pack('>H', value) for value in modbus_data)
            return byte_data.decode('utf-8')
        except (UnicodeDecodeError, struct.error) as e:
            logger.error(f"Error decoding Modbus data: {e}")
            return None

    @staticmethod
    def _bytes_to_integers(byte_list):
        logger.info(f'byte_list: {byte_list}')
        return [int.from_bytes(b, byteorder='big') for b in byte_list]

    @staticmethod
    def bytes_to_list_with_padding(data):
        chunks = [data[i:i+2] for i in range(0, len(data), 2)]
        if len(chunks[-1]) < 2:
            chunks[-1] = chunks[-1].ljust(2, b'0')
        return ntn_modbus_master._bytes_to_integers(chunks)

    @staticmethod
    def string_to_ascii_list(input_str):
        """Convert a string to a list of 16-bit ASCII values (big-endian pairs).
        Pads with NUL byte if the string length is odd.
        Example: '7000' -> [0x3730, 0x3030]
        """
        if len(input_str) % 2:
            input_str += '\x00'
        result = []
        for i in range(0, len(input_str), 2):
            pair = input_str[i:i+2]
            result.append((ord(pair[0]) << 8) | ord(pair[1]))
        return result

    def _at_command_to_ascii(self, cmd):
        """Convert AT command string to list of 16-bit ASCII values with padding."""
        ascii_codes = [ord(c) for c in cmd]
        if len(ascii_codes) % 2 != 0:
            ascii_codes.append(0)
        result = []
        for i in range(0, len(ascii_codes) - 1, 2):
            result.append((ascii_codes[i] << 8) + ascii_codes[i + 1])
        return result

    def pcie2_set_cmd(self, cmd):
        """Write an AT command to the PCIe2 (LoRa) module via Modbus register 0xC700."""
        try:
            if cmd is not None:
                ascii_cmd = self._at_command_to_ascii(cmd + '\r\n')
                logger.info(f'ASCII command: {ascii_cmd}')
                return self.set_registers(0xC700, ascii_cmd)
            return False
        except Exception as e:
            logger.info(e)
            return False

    def pcie2_cmd(self, cmd):
        """Send an AT command to the PCIe2 (LoRa) module and return the decoded response."""
        if cmd == 'AT+BISGET=?':
            reg_data_len = 0xF460
            reg_data_start = 0xF461
        else:
            reg_data_len = 0xF860
            reg_data_start = 0xF861

        time_to_wait = 5 if cmd == 'ATZ' else 3

        ret = self.pcie2_set_cmd(cmd)
        logger.info(f'Command: {cmd}, ret: {ret}')
        if not ret:
            return None

        sleep(time_to_wait)
        try:
            data_len_to_read = self.read_register(reg_data_len)
            logger.info(f'data length to read: {hex(reg_data_len)}, {data_len_to_read}')
            if not data_len_to_read:
                return None
            pcie2_data = self.read_registers(reg_data_start, data_len_to_read)
            if not pcie2_data:
                return None
            a_codes = []
            for d in pcie2_data:
                a_codes.append(d >> 8)
                a_codes.append(d & 0xFF)
            if cmd == 'AT+BISGET=?':
                idx_1st = a_codes.index(34)
                idx_2nd = a_codes.index(34, idx_1st + 1)
                a_codes = a_codes[idx_1st + 1:idx_2nd]
                logger.debug(f'a_codes: {a_codes}')
                return binascii.unhexlify(bytes(a_codes)).decode('utf8')
            else:
                logger.debug(f'a_codes: {a_codes}')
                return bytes(a_codes).decode('utf8')
        except Exception as e:
            logger.info(e)
            return None


def dl_read(ntn_dongle):
    """Continuously read downlink data from the device (runs in a daemon thread)."""
    while True:
        try:
            data_len = 0
            data_len = ntn_dongle.read_register(0xEC60)
            if data_len != 0:
                logger.info(f'Downlink data length: {data_len}')
                dl_resp = ntn_dongle.read_registers(0xEC61, data_len)
                logger.info(f'Downlink data response: {dl_resp}')
                dl_data = b''.join(struct.pack('>H', v) for v in dl_resp)
                dl_data = json.loads(binascii.unhexlify(dl_data).decode('utf-8'))
                logger.info(f'Downlink data: {dl_data}')
            else:
                logger.debug(f'Downlink data length: {data_len}')
                sleep(1)
        except Exception as e:
            logger.error(f"Error in downlink_modbus: {e}")
            sleep(1)


# === LoRa Configuration Handling ===
class LoraConfig:
    def __init__(self, ini_path='lora.ini'):
        self.ini_path = ini_path
        if not os.path.exists(self.ini_path):
            self._create_default_ini()
        self.config = configparser.ConfigParser()
        self.config.read(self.ini_path)

    def _create_default_ini(self):
        config = configparser.ConfigParser()
        config['LORA'] = {'frequency': '923200000', 'sf': '9', 'ch_plan': '0'}
        config['PRIVATE_KEY'] = {}
        config['PUBLIC_KEY'] = {}
        with open(self.ini_path, 'w') as f:
            config.write(f)

    def get_lora_params(self):
        lora = self.config['LORA'] if 'LORA' in self.config else {}
        return {
            'frequency': lora.get('frequency', '923200000'),
            'sf': lora.get('sf', '9'),
            'ch_plan': lora.get('ch_plan', '0')
        }

    def get_devices(self):
        section = 'PRIVATE_KEY' if 'PRIVATE_KEY' in self.config else 'DEVICES'
        return dict(self.config[section]) if section in self.config else {}

    def get_pubkey(self):
        if 'PUBLIC_KEY' in self.config and 'pubkey' in self.config['PUBLIC_KEY']:
            return self.config['PUBLIC_KEY']['pubkey']
        return None


def ntn_config(ntn_dongle, remote_port: str, apn: str, ip: str, local_port: str = None):
    """One-shot: authenticate then write UDP network parameters to device registers."""
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    logger.info(f'password: {passwd}')
    if not ntn_dongle.set_registers(0x0000, passwd):
        logger.error('Password set failed')
        sys.exit(1)
    logger.info('Password set successfully')

    sn = ntn_dongle.read_registers(0xEA60, 6)
    if not sn:
        logger.error('SN read failed')
        sys.exit(1)
    logger.info(f'SN: {sn}')

    def write_param(desc, reg, value):
        payload = ntn_modbus_master.string_to_ascii_list(value)
        if ntn_dongle.set_registers(reg, payload):
            logger.info(f'{desc} set to: {value}')
        else:
            logger.error(f'Failed to set {desc}')

    write_param('Remote port', 0xC3B8, remote_port)
    write_param('APN', 0xC3BB, apn)
    write_param('Remote IP', 0xC3CA, ip)
    write_param('Local port', 0xC3D5, local_port if local_port else '55001')


def ntn_info(ntn_dongle, args):
    """Authenticate, log UDP config registers (UDP mode only), then log device info and NTN metrics."""
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    logger.info(f'password: {passwd}')
    if not ntn_dongle.set_registers(0x0000, passwd):
        logger.error('Password set failed')
        sys.exit(1)
    logger.info('Password set successfully')

    def log_reg(desc, resp):
        if resp:
            logger.info(f'{desc}: {ntn_modbus_master.modbus_data_to_string(resp)}')

    if args.type == 'UDP':
        log_reg('remote port', ntn_dongle.read_registers(0xC3B8, 3, functioncode=3))
        log_reg('APN Name',    ntn_dongle.read_registers(0xC3BB, 15, functioncode=3))
        log_reg('remote IP',   ntn_dongle.read_registers(0xC3CA, 8, functioncode=3))
        log_reg('local port',  ntn_dongle.read_registers(0xC3D5, 3, functioncode=3))

    log_reg('SN', ntn_dongle.read_registers(0xEA60, 6))
    log_reg('Model Name', ntn_dongle.read_registers(0xEA66, 5))
    log_reg('FW ver', ntn_dongle.read_registers(0xEA6B, 2))
    log_reg('HW Ver', ntn_dongle.read_registers(0xEA6D, 2))
    modbus_id = ntn_dongle.read_register(0xEA6F)
    if modbus_id:
        logger.info(f'Modbus ID: {modbus_id}')
    heartbeat = ntn_dongle.read_register(0xEA70)
    if heartbeat:
        logger.info(f'Heartbeat: {heartbeat}')
    log_reg('IMSI', ntn_dongle.read_registers(0xEB00, 8))
    log_reg('SINR', ntn_dongle.read_registers(0xEB13, 2))
    log_reg('RSRP', ntn_dongle.read_registers(0xEB15, 2))
    log_reg('Latitude', ntn_dongle.read_registers(0xEB1B, 5))
    log_reg('Longitude', ntn_dongle.read_registers(0xEB20, 6))


def setup_lora(ntn_dongle, lora_conf, args):
    """Configure the LoRa co-module (A2 hardware) based on lora.ini and CLI flags."""
    logger.info('--- LoRa Setup ---')
    data = ntn_dongle.pcie2_cmd('AT+BISFMT=1')
    logger.info(f'response: {data}')
    params = lora_conf.get_lora_params()
    freq, sf, ch = params['frequency'], params['sf'], params['ch_plan']
    ch_plan_map = {"AS923": 0, "US915": 1, "AU915": 2, "EU868": 3, "KR920": 4, "IN865": 5, "RU864": 6}

    if args.lora_setup:
        data = ntn_dongle.pcie2_cmd('AT+BISRXF=?')
        freq_onDev = re.split(r'[:\s\n]+', data)[2]
        logger.info(f'response: {freq_onDev}')
        if freq != freq_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISRXF=' + freq)
            logger.info(f'response: {data}')
        data = ntn_dongle.pcie2_cmd('AT+BISRXSF=?')
        sf_onDev = re.split(r'[:\s\n]+', data)[2]
        logger.info(f'response: {sf_onDev}')
        if sf != sf_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISRXSF=' + sf)
            logger.info(f'response: {data}')
        data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN=?')
        ch_onDev = ch_plan_map.get(re.split(r'[:\s\n]+', data)[2], 0)
        logger.info(f'response: {ch_onDev}')
        if int(ch) != ch_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN=' + ch)
            logger.info(f'response: {data}')

    if args.lora_privkey_setup:
        devices = lora_conf.get_devices()
        logger.info(f'LoRa devices: {devices}')
        for k, v in devices.items():
            logger.debug(f'AT+BISDEV={v}')
            data = ntn_dongle.pcie2_cmd('AT+BISDEV=' + v)
            logger.debug(f'response: {data}')

    if args.lora_privkey_cleanup:
        for i in range(16):
            cmd = f'AT+BISDEV={i}:ffffffff:ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff'
            data = ntn_dongle.pcie2_cmd(cmd)
            logger.info(f'response: {data}')

    if args.lora_pubkey_setup:
        pubkey = lora_conf.get_pubkey()
        if pubkey:
            data = ntn_dongle.pcie2_cmd('AT+BISADMIN=' + pubkey)
            logger.info(f'response: {data}')

    if args.lora_pubkey_cleanup:
        data = ntn_dongle.pcie2_cmd('AT+BISADMIN=ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff')
        logger.info(f'response: {data}')

    data = ntn_dongle.pcie2_cmd('AT+BISS')
    logger.info(f'response: {data}')
    data = ntn_dongle.pcie2_cmd('ATZ')
    logger.info(f'response: {data}')


def lora_privkey_query(ntn_dongle):
    """Query and log LoRa private key slot 0."""
    for i in range(16):
        cmd = f'AT+BISDEV={i}?'
        data = ntn_dongle.pcie2_cmd(cmd)
        if data:
            logger.info(f'Lora device {i}: {data}')
        else:
            logger.error(f'Lora device {i} query failed')


def ntn_status_loop(ntn_dongle, args, lora_conf):
    """Main status loop: poll NTN status, upload telemetry, poll LoRa, then sleep --interval seconds."""
    while True:
        net_status = False
        ntn_status = ntn_dongle.read_register(0xEA71)
        if ntn_status:
            if args.type == 'NIDD':
                module_at_ready = ntn_status & 0x01
                downlink_ready = (ntn_status & 0x02) >> 1
                sim_ready = (ntn_status & 0x04) >> 2
                network_registered = (ntn_status & 0x08) >> 3
                logger.info('=== NTN dongle status ===')
                logger.info(f'{module_at_ready=}')
                logger.info(f'{downlink_ready=}')
                logger.info(f'{sim_ready=}')
                logger.info(f'{network_registered=}')
                if (ntn_status & 0xF) == 0xF:
                    net_status = True
            elif args.type == 'UDP':
                module_at_ready = ntn_status & 0x01
                ip_ready = (ntn_status & 0x02) >> 1
                sim_ready = (ntn_status & 0x04) >> 2
                network_registered = (ntn_status & 0x08) >> 3
                socket_ready = (ntn_status & 0x10) >> 4
                logger.info('=== NTN dongle status ===')
                logger.info(f'{module_at_ready=}')
                logger.info(f'{ip_ready=}')
                logger.info(f'{sim_ready=}')
                logger.info(f'{network_registered=}')
                logger.info(f'{socket_ready=}')
                if (ntn_status & 0x1F) == 0x1F:
                    net_status = True
            else:
                logger.error(f'Wrong NTN type: {args.type}')

        avbl = ntn_dongle.read_register(0xEA7D)
        logger.info(f'{avbl=}')
        upload_avbl = ntn_dongle.read_register(0xEA7D) == 0

        if net_status and upload_avbl:
            if args.upload:
                packets = []

                if args.ud_type in ('signal', 'all'):
                    signal_list = []
                    rsrp_resp = ntn_dongle.read_registers(0xEB15, 2)
                    if rsrp_resp:
                        logger.info(f'rsrp_resp: {rsrp_resp}')
                        rsrp = ntn_modbus_master.modbus_data_to_string(rsrp_resp)
                        if rsrp:
                            logger.info(f'RSRP: {repr(rsrp)}')
                            signal_list.append(int(rsrp))
                    sinr_resp = ntn_dongle.read_registers(0xEB13, 2)
                    if sinr_resp:
                        sinr = ntn_modbus_master.modbus_data_to_string(sinr_resp)
                        if sinr:
                            logger.info(f'SINR: {sinr}')
                            signal_list.append(int(sinr))
                    if signal_list:
                        packets.append({'c': signal_list})

                if args.ud_type in ('gps', 'all'):
                    gps_list = []
                    lat_resp = ntn_dongle.read_registers(0xEB1B, 5)
                    if lat_resp:
                        lat = ntn_modbus_master.modbus_data_to_string(lat_resp)
                        if lat:
                            logger.info(f'Latitude: {lat}')
                            gps_list.append(float(lat))
                    long_resp = ntn_dongle.read_registers(0xEB20, 6)
                    if long_resp:
                        long = ntn_modbus_master.modbus_data_to_string(long_resp)
                        if long:
                            logger.info(f'Longitude: {long}')
                            gps_list.append(float(long))
                    if gps_list:
                        packets.append({'g': gps_list})

                for data in packets:
                    d_str = json.dumps(data)
                    logger.info(f'd_str: {d_str}')
                    d_bytes = d_str.encode('utf-8')
                    logger.info(f'd_bytes: {d_bytes}')
                    d_hex = binascii.hexlify(d_bytes)
                    logger.info(f'packet: {d_hex}')
                    d_hex += b'\r\n'
                    modbus_data = ntn_modbus_master.bytes_to_list_with_padding(d_hex)
                    logger.info(f'modbus data: {modbus_data}')
                    response = ntn_dongle.set_registers(0xC550, modbus_data)
                    logger.info(f'response: {response}')
                    if response:
                        while True:
                            data_len = ntn_dongle.read_register(0xF060)
                            if data_len != 0:
                                logger.info(f'reply data len: {data_len}')
                                data_resp = ntn_dongle.read_registers(0xF061, data_len)
                                logger.info(f'responsed data: {data_resp}')
                                if data_resp:
                                    uplink_resp = ntn_modbus_master.modbus_data_to_string(data_resp)
                                    logger.info(f'Uplink response: {uplink_resp}')
                                break
                            else:
                                sleep(1)

        if args.lora:
            devices = lora_conf.get_devices()
            for i in range(len(devices)):
                data = ntn_dongle.pcie2_cmd('AT+BISGET=?')
                logger.info(f'{data=}')

        sleep(args.interval)


def main():
    args = parse_arguments()
    logger.info(f'WARNING *** NTN dongle mode: "{args.type}" | interval: {args.interval}s ***')
    NTN_DONGLE_ADDR = 1
    lora_conf = LoraConfig()
    try:
        ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port=args.port, baudrate=115200)
        if args.dl:
            dl_thread = threading.Thread(target=dl_read, args=(ntn_dongle,), daemon=True)
            dl_thread.start()
        # One-shot UDP device config mode
        if args.ntn_config:
            if not all([args.remote_port, args.apn, args.ip]):
                logger.error('Please provide --remote_port, --apn, and --ip for configuration.')
                sys.exit(1)
            ntn_config(ntn_dongle, args.remote_port, args.apn, args.ip, args.local_port)
            logger.info('NTN dongle configured successfully.')
            logger.info('Please unplug the NTN dongle and plug it back in to apply new settings.')
            return
        ntn_info(ntn_dongle, args)
        # LoRa setup (A2 hardware)
        if any([args.lora_setup, args.lora_privkey_cleanup, args.lora_privkey_setup,
                args.lora_pubkey_setup, args.lora_pubkey_cleanup]):
            setup_lora(ntn_dongle, lora_conf, args)
        if args.lora_privkey_query:
            lora_privkey_query(ntn_dongle)
        ntn_status_loop(ntn_dongle, args, lora_conf)
    except Exception as e:
        logger.error(f'{e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
