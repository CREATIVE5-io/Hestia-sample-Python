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
    parser.add_argument("--type", type=str, help="Specify NIDD or UDP", default='NIDD')
    parser.add_argument("--port", type=str, help="Specify port", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test", default=False)
    parser.add_argument("--dl", action='store_true', help="Enable downlink test", default=False)
    return parser.parse_args()

# === Globals ===
PORT_LOCK = threading.Lock()
logger = modbus_tk.utils.create_logger('console')

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

def setup_ntn_device(ntn_dongle):
    """Set up the NTN dongle: password, info, and log device details."""
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

def ntn_status_loop(ntn_dongle, args):
    """Main status loop: monitor status and handle upload if enabled."""
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
                logger.error(f'Wrong NTN type, input is :{args.type}')

        avbl = ntn_dongle.read_register(0xEA7D)
        logger.info(f'{avbl=}')
        upload_avbl = True if ntn_dongle.read_register(0xEA7D)==0 else False

        if net_status and upload_avbl:
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
        sleep(10*60)

def main():
    args = parse_arguments()
    logger.info(f'WARNING *** You set to run NTN dongle on "{args.type}" mode ***')
    NTN_DONGLE_ADDR = 1
    try:
        ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port=args.port, baudrate=115200)
        if args.dl:
            dl_thread = threading.Thread(target=dl_read, args=(ntn_dongle,))
            dl_thread.start()
        setup_ntn_device(ntn_dongle)
        ntn_status_loop(ntn_dongle, args)
    except Exception as e:
        logger.error(f'{e} - Code={e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
