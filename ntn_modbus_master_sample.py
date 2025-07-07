
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
    parser.add_argument("--type", type=str, help="Specify NIDD or UDP", default='NIDD')
    parser.add_argument("--port", type=str, help="Specify port", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test", default=False)
    parser.add_argument("--dl", action='store_true', help="Enable downlink test", default=False)
    parser.add_argument("--lora", action='store_false', help="Disable lora get data", default=True)
    parser.add_argument("--lora_setup", action='store_true', help="Enable lora module setup", default=False)
    parser.add_argument("--lora_privkey_query", action='store_true', help="Query lora private keys", default=False)
    parser.add_argument("--lora_privkey_setup", action='store_true', help="Enable to setup lora private keys", default=False)
    parser.add_argument("--lora_privkey_cleanup", action='store_true', help="Cleanup lora private keys", default=False)
    parser.add_argument("--lora_pubkey_setup", action='store_true', help="Setup lora public key", default=False)
    parser.add_argument("--lora_pubkey_cleanup", action='store_true', help="Cleanup lora public key", default=False)
    return parser.parse_args()

g_args = parse_arguments()

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
                value=self.master.execute(self.slaveAddr, functioncode, reg, 1)
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
                if val != None:
                    value = self.master.execute(self.slaveAddr, cst.WRITE_MULTIPLE_REGISTERS, reg, output_value=val)
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

    def _at_command_to_ascii(self, cmd):
        """
        Convert AT command string to list of ASCII codes
        Args:
            command (str): AT command string
        Returns:
            list: List of ASCII codes with padding
        """
        ascii_codes = []
        result = []
        for char in cmd:
            ascii_codes.append(ord(char))
        if len(ascii_codes)%2 != 0:
            ascii_codes.append(0)

        # Process pairs of bytes
        for i in range(0, len(ascii_codes)-1, 2):
            # Shift first byte left 8 bits and add second byte
            combined = (ascii_codes[i] << 8) + ascii_codes[i + 1]
            result.append(combined)
        return result

    def pcie2_set_cmd(self, cmd):
        """ Set command to PCIe2 module """
        try:
            if cmd != None:
                # Convert AT command to ASCII codes
                cmd = cmd+'\r\n'
                ascii_cmd = self._at_command_to_ascii(cmd)
                logger.info(f'ASCII command: {ascii_cmd}')
                value = self.set_registers(0xC700, ascii_cmd)
                return value
            else:
                return False
        except Exception as e:
            logger.info(e)
            return False

    def pcie2_cmd(self, cmd):
        data = None
        if cmd == 'AT+BISGET=?':
            reg_data_len = 0xF460
            reg_data_start = 0xF461
        else:
            reg_data_len = 0xF860
            reg_data_start = 0xF861

        if cmd == 'ATZ':
            time_to_wait = 5
        else:
            time_to_wait = 3

        """ Send command to PCIe2 module """
        ret = self.pcie2_set_cmd(cmd)
        logger.info(f'Command: {cmd}, ret: {ret}')
        if ret:
            sleep(time_to_wait)
            data_len_to_read = 0
            try:
                # Read response from PCIe2 module
                data_len_to_read = self.read_register(reg_data_len)
                logger.info(f'data length to read: {hex(reg_data_len)}, {data_len_to_read}')
                if data_len_to_read:
                    logger.info(f'data length to read: {data_len_to_read}')
                    a_codes = []
                    pcie2_data = self.read_registers(reg_data_start, data_len_to_read)
                    if pcie2_data:
                        for d in pcie2_data:
                            a_codes.append(d >> 8)
                            a_codes.append(d&0xFF)
                        if cmd == 'AT+BISGET=?':
                            idx_1st = a_codes.index(34)
                            logger.debug(f'Index: {idx_1st}')
                            idx_2nd = a_codes.index(34, idx_1st+1)
                            logger.debug(f'Index: {idx_2nd}')
                            a_codes = a_codes[idx_1st+1:idx_2nd]
                            logger.debug(f'a_codes: {a_codes}')
                            data = binascii.unhexlify(bytes(a_codes)).decode('utf8')
                        else:
                            logger.debug(f'a_codes: {a_codes}')
                            data = bytes(a_codes).decode('utf8')
                    else:
                        data = None
            except Exception as e:
                logger.info(e)
                return None
        return data

def dl_read(ntn_dongle):
    while True:
        try:
            data_len = 0
            # Check Downlink Data Size
            data_len = ntn_dongle.read_register(0xEC60)
            if data_len != 0:
                logger.info(f'Downlink data length: {data_len}')
                # Read Downlink Data
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
            # Create a default lora.ini if it doesn't exist
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

def setup_ntn_device(ntn_dongle):
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    logger.info(f'password: {passwd}')
    valid_passwd = ntn_dongle.set_registers(0x0000, passwd)
    if not valid_passwd:
        logger.error(f'Password set failed')
        sys.exit(1)
    logger.info(f'Password set successfully')

    def log_reg(desc, resp):
        if resp:
            logger.info(f'{desc}: {ntn_modbus_master.modbus_data_to_string(resp)}')

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
    logger.info('--- LoRa Setup ---')
    data = ntn_dongle.pcie2_cmd('AT+BISFMT=1')
    logger.info(f'response: {data}')
    params = lora_conf.get_lora_params()
    freq, sf, ch = params['frequency'], params['sf'], params['ch_plan']
    ch_plan_map = {"AS923": 0, "US915": 1, "AU915": 2, "EU868": 3, "KR920": 4, "IN865": 5, "RU864": 6}

    if args.lora_setup:
        # Setup LoRa module
        data = ntn_dongle.pcie2_cmd('AT+BISRXF=?')
        freq_onDev = re.split(r'[:\s\n]+', data)[2]
        logger.info(f'response: {freq_onDev}')
        if freq != freq_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISRXF='+freq)
            logger.info(f'response: {data}')
        data = ntn_dongle.pcie2_cmd('AT+BISRXSF=?')
        sf_onDev = re.split(r'[:\s\n]+', data)[2]
        logger.info(f'response: {sf_onDev}')
        if sf != sf_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISRXSF='+sf)
            logger.info(f'response: {data}')
        data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN=?')
        ch_onDev = ch_plan_map.get(re.split(r'[:\s\n]+', data)[2], 0)
        logger.info(f'response: {ch_onDev}')
        if int(ch) != ch_onDev:
            data = ntn_dongle.pcie2_cmd('AT+BISCHPLAN='+ch)
            logger.info(f'response: {data}')

    if args.lora_privkey_setup:
        devices = lora_conf.get_devices()
        logger.info(f'LoRa devices: {devices}')
        for k, v in devices.items():
            logger.debug(f'AT+BISDEV={v}')
            data = ntn_dongle.pcie2_cmd('AT+BISDEV='+v)
            logger.debug(f'response: {data}')

    if args.lora_privkey_cleanup:
        for i in range(16):
            cmd = f'AT+BISDEV={i}:ffffffff:ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff'
            data = ntn_dongle.pcie2_cmd(cmd)
            logger.info(f'response: {data}')

    if args.lora_pubkey_setup:
        pubkey = lora_conf.get_pubkey()
        if pubkey:
            data = ntn_dongle.pcie2_cmd('AT+BISADMIN='+pubkey)
            logger.info(f'response: {data}')

    if args.lora_pubkey_cleanup:
        data = ntn_dongle.pcie2_cmd('AT+BISADMIN=ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff')
        logger.info(f'response: {data}')

    data = ntn_dongle.pcie2_cmd('AT+BISS')
    logger.info(f'response: {data}')
    data = ntn_dongle.pcie2_cmd('ATZ')
    logger.info(f'response: {data}')

def lora_privkey_query(ntn_dongle):
    for i in range(1):
        cmd = f'AT+BISDEV={i}?'
        data = ntn_dongle.pcie2_cmd(cmd)
        if data:
            logger.info(f'Lora device {i}: {data}')
        else:
            logger.error(f'Lora device {i} query failed')

def ntn_status_loop(ntn_dongle, args, lora_conf):
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
                if ntn_status == 0xF:
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
                if ntn_status == 0x1F:
                    net_status = True
            else:
                logger.error(f'Wrong NTN type, input is :{args.type}')

        if net_status:
            if args.upload:
                data_list = []
                rsrp_resp = ntn_dongle.read_registers(0xEB15, 2)
                if rsrp_resp:
                    logger.info(f'rsrp_resp: {rsrp_resp}')
                    rsrp = ntn_modbus_master.modbus_data_to_string(rsrp_resp)
                    if rsrp:
                        logger.info(f'RSRP: {repr(rsrp)}')
                        data_list.append(int(rsrp))
                sinr_resp = ntn_dongle.read_registers(0xEB13, 2)
                if sinr_resp:
                    sinr = ntn_modbus_master.modbus_data_to_string(sinr_resp)
                    if sinr:
                        logger.info(f'SINR: {sinr}')
                        data_list.append(int(sinr))
                if data_list:
                    data = {'c': data_list}
                    d_str = json.dumps(data)
                    logger.info(f'd_str: {d_str}')
                    d_bytes = d_str.encode('utf-8')
                    logger.info(f'd_bytes: {d_bytes}')
                    d_hex = binascii.hexlify(d_bytes)
                    logger.info(f'packet: {d_hex}')
                    modbus_data = ntn_modbus_master.bytes_to_list_with_padding(d_hex)
                    modbus_data.extend([3338])
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
        sleep(10*60)

def main():
    args = parse_arguments()
    logger.info(f'WARNING *** You set to run NTN dongle on "{args.type}" mode ***')
    NTN_DONGLE_ADDR = 1
    lora_conf = LoraConfig()
    ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port=args.port, baudrate=115200)
    if args.dl:
        dl_thread = threading.Thread(target=dl_read, args=(ntn_dongle,))
        dl_thread.start()
    setup_ntn_device(ntn_dongle)
    if any([args.lora_setup, args.lora_privkey_cleanup, args.lora_privkey_setup, args.lora_pubkey_setup, args.lora_pubkey_cleanup]):
        setup_lora(ntn_dongle, lora_conf, args)
    if args.lora_privkey_query:
        lora_privkey_query(ntn_dongle)
    ntn_status_loop(ntn_dongle, args, lora_conf)

if __name__ == '__main__':
    main()
