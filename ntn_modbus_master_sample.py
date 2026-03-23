import argparse
import binascii
import json
import logging
import modbus_tk
import modbus_tk.defines as cst
import modbus_tk.modbus_rtu as modbus_rtu
import os
import re
import serial
import struct
import sys
import threading
from time import sleep
from time import time

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="NTN-MODBUS-MASTER-TEST")
    parser.add_argument("--ntn_config", action='store_true', help="NTN dongle config", default=False)
    parser.add_argument("--remote_port", type=str, help="Specify remote port", default='')
    parser.add_argument("--apn", type=str, help="Specify APN", default='')
    parser.add_argument("--ip", type=str, help="Specify IP", default='')
    parser.add_argument("--local_port", type=str, help="Specify local port", default='')
    parser.add_argument("--port", type=str, help="Specify port", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test", default=False)
    parser.add_argument("--dl", action='store_true', help="Enable downlink test", default=False)
    parser.add_argument("--bin_file", type=str, help="Binary file to upload via NTN dongle", default=None)
    return parser.parse_args()

# === Globals ===
PORT_LOCK = threading.Lock()
logger = modbus_tk.utils.create_logger('console')

# Uplink register map (per register table)
UPLINK_PART_ADDRS = [0xC550, 0xC590, 0xC5D0, 0xC610, 0xC650]
UPLINK_CHUNK_SIZE = 64  # bytes per part (64 registers × 2 bytes)

class ntn_modbus_master:
    """Modbus RTU master for NTN dongle communication."""
    def __init__(self, slaveAddress, port, baudrate=115200, bytesize=8, parity='N', stopbits=1, xonxoff=0):
        try:
            self.master = modbus_rtu.RtuMaster(serial.Serial(port = port, baudrate = baudrate, bytesize = bytesize, parity = parity, stopbits = stopbits, xonxoff = xonxoff))
            self.master.set_timeout(1)
            self.master.set_verbose(False)
            self.slaveAddr = slaveAddress
            self.lock = threading.Lock()
            logger.info('NTN dongle init!')
        except modbus_tk.modbus.ModbusError as e:
            logger.error(f'{e} - Code={e.get_exception_code()}')
            raise (e)

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
            """ int => byte """
            byte_data = b''.join(struct.pack('>H', value) for value in modbus_data)
            """ byte => str """
            result_str = byte_data.decode('utf-8')
            return result_str
        except (UnicodeDecodeError, struct.error) as e:
            logger.error(f"Error decoding Modbus data: {e}")
            return None

    @staticmethod
    def _bytes_to_integers(byte_list):
        """ Convert each 2-byte string to an integer """
        logger.info(f'byte_list: {byte_list}')
        return [int.from_bytes(b, byteorder='big') for b in byte_list]

    @staticmethod
    def bytes_to_list_with_padding(data):
        """ Split the data into 2-byte chunks """
        chunks = [data[i:i+2] for i in range(0, len(data), 2)]
        """ Pad the last chunk with a zero byte if needed """
        chunks[-1] = chunks[-1].ljust(2, b'0')
        return ntn_modbus_master._bytes_to_integers(chunks)

    @staticmethod
    def string_to_ascii_list(input_str):
        """Convert a string to a list of 16-bit ASCII values.
        Each element in the output list represents two ASCII characters.
        If the string length is odd, it's padded with a NUL byte ("\x00").
        Example:
            '7000' -> [0x3730, 0x3030]  # '70' -> 0x3730, '00' -> 0x3030
            '700'  -> [0x3730, 0x3000]  # '70' -> 0x3730, '0' + '\x00' -> 0x3000
        """
        # Pad with NUL byte if odd length so the last pair becomes <char><NUL>
        if len(input_str) % 2:
            input_str += '\x00'

        # Convert pairs of characters to 16-bit integers (big-endian)
        result = []
        for i in range(0, len(input_str), 2):
            pair = input_str[i:i+2]
            ascii_val = (ord(pair[0]) << 8) | ord(pair[1])
            result.append(ascii_val)
        return result

def upload_bin_file(ntn_dongle, filepath):
    """Upload a binary file via NTN dongle using multi-part Modbus registers.

    Data is split into UPLINK_CHUNK_SIZE-byte chunks. Each chunk is hex-encoded
    (doubling to 128 bytes / 64 registers) and written to successive part addresses
    (0xC550, 0xC590, ...). The last two hex bytes of the final chunk are replaced
    with \\r\\n appended as a terminator.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except OSError as e:
        logger.error(f'Failed to read {filepath}: {e}')
        return False

    logger.info(f'Uploading binary: {filepath} ({len(data)} bytes)')
    if len(data) < 2:
        logger.error('File too small (need at least 2 bytes)')
        return False

    chunks = [data[i:i+UPLINK_CHUNK_SIZE] for i in range(0, len(data), UPLINK_CHUNK_SIZE)]
    if len(chunks) > len(UPLINK_PART_ADDRS):
        logger.error(f'File too large ({len(data)} bytes); max {len(UPLINK_PART_ADDRS) * UPLINK_CHUNK_SIZE} bytes')
        return False

    for i, (chunk, addr) in enumerate(zip(chunks, UPLINK_PART_ADDRS)):
        d_hex = binascii.hexlify(chunk)
        if i == len(chunks) - 1:
            d_hex = d_hex + b'\r\n'  # append CRLF terminator to last chunk
        modbus_data = ntn_modbus_master.bytes_to_list_with_padding(d_hex)
        logger.info(f'Part {i+1}: addr=0x{addr:04X}, {len(modbus_data)} regs')
        if not ntn_dongle.set_registers(addr, modbus_data):
            logger.error(f'Failed to write uplink part {i+1}')
            return False

    logger.info('Binary upload sent')
    return True

def dl_read(ntn_dongle):
    """Continuously read downlink data from the device."""
    while True:
        try:
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

def ntn_config(ntn_dongle, remote_port:str, apn:str, ip:str, local_port:str=None):
    """Set up the NTN dongle: password, info, and log device details."""
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    logger.info(f'password: {passwd}')
    valid_passwd = ntn_dongle.set_registers(0x0000, passwd)
    if not valid_passwd:
        logger.error(f'Password set failed')
        sys.exit(1)
    logger.info(f'Password set successfully')

    """Configure the NTN dongle with specific settings."""
    sn = ntn_dongle.read_registers(0xEA60, 6)
    if not sn:
        logger.error(f'SN read failed')
        sys.exit(1)
    logger.info(f'SN: {sn}')

    payload = ntn_modbus_master.string_to_ascii_list(remote_port)
    ret = ntn_dongle.set_registers(0xC3B8, payload)
    if ret:
        logger.info(f'Remote port set to: {remote_port}')
    else:
        logger.error(f'Failed to set remote port')

    payload = ntn_modbus_master.string_to_ascii_list(apn)
    ret = ntn_dongle.set_registers(0xC3BB, payload)
    if ret:
        logger.info(f'APN set to: {apn}')
    else:
        logger.error(f'Failed to set APN')

    payload = ntn_modbus_master.string_to_ascii_list(ip)
    ret = ntn_dongle.set_registers(0xC3CA, payload)
    if ret:
        logger.info(f'IP set to: {ip}')
    else:
        logger.error(f'Failed to set IP')

    if local_port is None:
        local_port = '55001'
    payload = ntn_modbus_master.string_to_ascii_list(local_port)
    ret = ntn_dongle.set_registers(0xC3D5, payload)
    if ret:
        logger.info(f'Local port set to: {local_port}')
    else:
        logger.error(f'Failed to set local port')

def ntn_info(ntn_dongle):
    """Set up the NTN dongle: password, info, and log device details."""
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    logger.info(f'password: {passwd}')
    valid_passwd = ntn_dongle.set_registers(0x0000, passwd)
    if not valid_passwd:
        logger.error(f'Password set failed')
        sys.exit(1)
    logger.info(f'Password set successfully')

    """Set up the NTN dongle: password, info, and log device details."""
    sn = ntn_dongle.read_registers(0xEA60, 6)
    if not sn:
        logger.error(f'SN read failed')
        sys.exit(1)

    def log_reg(desc, resp):
        if resp:
            logger.info(f'{desc}: {ntn_modbus_master.modbus_data_to_string(resp)}')
    log_reg('remote port: ', ntn_dongle.read_registers(0xC3B8, 3, functioncode=3))
    log_reg('APN Name: ', ntn_dongle.read_registers(0xC3BB, 15, functioncode=3))
    log_reg('remote IP: ', ntn_dongle.read_registers(0xC3CA, 8, functioncode=3))
    log_reg('local port: ', ntn_dongle.read_registers(0xC3D5, 3, functioncode=3))

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

def ntn_status_loop(ntn_dongle, args):
    """Main status loop: monitor status and handle upload if enabled."""
    while True:
        net_status = False
        ntn_status = ntn_dongle.read_register(0xEA71)
        if ntn_status:
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

        if net_status:
            if args.bin_file:
                if upload_bin_file(ntn_dongle, args.bin_file):
                    while True:
                        data_len = ntn_dongle.read_register(0xF060)
                        if data_len != 0:
                            logger.info(f'reply data len: {data_len}')
                            data_resp = ntn_dongle.read_registers(0xF061, data_len)
                            if data_resp:
                                uplink_resp = ntn_modbus_master.modbus_data_to_string(data_resp)
                                logger.info(f'Uplink response: {uplink_resp}')
                            break
                        else:
                            sleep(1)
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
        sleep(30)

def main():
    args = parse_arguments()
    NTN_DONGLE_ADDR = 1
    try:
        ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port=args.port, baudrate=115200)
        if args.dl:
            dl_thread = threading.Thread(target=dl_read, args=(ntn_dongle,))
            dl_thread.start()
        if args.ntn_config:
            print(f'Remote port: {args.remote_port}')
            print(f'APN: {args.apn}')
            print(f'IP: {args.ip}')
            print(f'Local port: {args.local_port}')
            if args.remote_port == '' or args.apn == '' or args.ip == '':
                logger.error(f'Please provide remote_port, apn, and ip for configuration.')
                sys.exit(1)
            ntn_config(ntn_dongle, args.remote_port, args.apn, args.ip, args.local_port)
            logger.info(f'NTN dongle configured successfully.')
            logger.info(f'Please unplug the NTN dongle and plug it back in to apply new settings.')
            return
        ntn_info(ntn_dongle)
        ntn_status_loop(ntn_dongle, args)
    except Exception as e:
        logger.error(f'{e} - Code={e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
