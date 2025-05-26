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
    parser = argparse.ArgumentParser(description="NTN-MODBUS-MASTER-TEST")
    parser.add_argument("--port", type=str, help="Specify port", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test", default=False)
    parser.add_argument("--dl", action='store_true', help="Enable downlink test", default=False)
    return parser.parse_args()

g_args = parse_arguments()

""" Cretet theading lock to control modbus port access """
PORT_LOCK = threading.Lock()

logger = modbus_tk.utils.create_logger('console')

class ntn_modbus_master():
    def __init__(self, slaveAddress, port, baudrate=115200, bytesize=8, parity='N', stopbits=1, xonxoff=0):
        try:
            self.master = modbus_rtu.RtuMaster(serial.Serial(port = port, baudrate = baudrate, bytesize = bytesize, parity = parity, stopbits = stopbits, xonxoff = xonxoff))
            self.master.set_timeout(1)
            self.master.set_verbose(False)
            self.slaveAddr = slaveAddress
            logger.info('NTN dongle init!')
        except modbus_tk.modbus.ModbusError as e:
            logger.error(f'{e} - Code={e.get_exception_code()}')
            raise (e)

    def read_register(self, reg, functioncode=cst.READ_INPUT_REGISTERS):
        try:
            value=self.master.execute(self.slaveAddr, functioncode, reg, 1)
            return value[0]
        except Exception as e:
            logger.info(e)
            return None

    def read_registers(self, reg, num, functioncode=cst.READ_INPUT_REGISTERS):
        try:
            #value = []
            values = self.master.execute(self.slaveAddr, functioncode, reg, num)
            #print(type(values))
            #value = list(values)
            return values
        except Exception as e:
            logger.info(e)
            return None

    def set_registers(self, reg, val):
        try:
            if val != None:
                value = self.master.execute(self.slaveAddr, cst.WRITE_MULTIPLE_REGISTERS, reg, output_value=val)
                return True
            else:
                return False
        except Exception as e:
            logger.info(e)
            return False

#modbus_registers = {
#    'Serial_Number': {'address': 0xEA60, 'length': 6},
#    'Model_Name': {'address': 0xEA66, 'length': 5},
#    'Firmware_Version': {'address': 0xEA6B, 'length': 2},
#    'Hardware_Version': {'address': 0xEA6D, 'length': 2},
#    'Modbus_ID': {'address': 0xEA6F, 'length': 1},
#    'Heartbeat': {'address': 0xEA70, 'length': 1},
#    'NTN_Module_Status': {'address': 0xEA71, 'length': 1},
#    'PCIe2_Module_Status': {'address': 0xEA72, 'length': 1},
#    'NTN_IMSI': {'address': 0xEB00, 'length': 8},
#    'NTN_Software_Version': {'address': 0xEB08, 'length': 10},
#    'NTN_CSQ_SINR': {'address': 0xEB13, 'length': 2},
#    'NTN_CSQ_RSRP': {'address': 0xEB15, 'length': 2},
#    'NTN_Module_Time': {'address': 0xEB17, 'length': 4},
#    'NTN_GPS_Latitude': {'address': 0xEB1B, 'length': 5},
#    'NTN_GPS_Longitude': {'address': 0xEB20, 'length': 5},
#    'NTN_CSQ_Classification': {'address': 0xEB25, 'length': 3}
#}

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

def bytes_to_integers(byte_list):
    """ Convert each 2-byte string to an integer """
    logger.info(f'byte_list: {byte_list}')
    return [int.from_bytes(b, byteorder='big') for b in byte_list]

def bytes_to_list_with_padding(data):
    """ Split the data into 2-byte chunks """
    chunks = [data[i:i+2] for i in range(0, len(data), 2)]
    """ Pad the last chunk with a zero byte if needed """
    chunks[-1] = chunks[-1].ljust(2, b'0')
    return bytes_to_integers(chunks)

def dl_read(ntn_dongle):
    while True:
        try:
            data_len = 0
            PORT_LOCK.acquire()
            # Check Downlink Data Size
            data_len = ntn_dongle.read_register(0xEC60)
            PORT_LOCK.release()
            if data_len != 0:
                logger.info(f'Downlink data length: {data_len}')
                PORT_LOCK.acquire()
                # Read Downlink Data
                dl_resp = ntn_dongle.read_registers(0xEC61, data_len)
                PORT_LOCK.release()
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

def main():
    NTN_DONGLE_ADDR = 1
    try:
        ntn_dongle = ntn_modbus_master(NTN_DONGLE_ADDR, port = g_args.port, baudrate=115200)
        if g_args.dl:
            dl_thread = threading.Thread(target = dl_read, args = (ntn_dongle,))
            dl_thread.start()

        DEFAULT_PASSWD = '00000000'
        with PORT_LOCK:
            passwd = []
            for i in range(0, len(DEFAULT_PASSWD), 2):
                passwd.append(int(DEFAULT_PASSWD[i:i+2]))
            logger.info(f'password: {passwd}')
            ntn_dongle.set_registers(0x0000, passwd)

        # SN
        with PORT_LOCK:
            sn_resp = ntn_dongle.read_registers(0xEA60, 6)
            logger.info(f'SN: {modbus_data_to_string(sn_resp)}')
        # Model Name
        with PORT_LOCK:
            model_name_resp = ntn_dongle.read_registers(0xEA66, 5)
            logger.info(f'Model Name: {modbus_data_to_string(model_name_resp)}')
        # FW version
        with PORT_LOCK:
            fw_ver_resp = ntn_dongle.read_registers(0xEA6B, 2)
            logger.info(f'FW ver: {modbus_data_to_string(fw_ver_resp)}')
        # HW version
        with PORT_LOCK:
            hw_ver_resp = ntn_dongle.read_registers(0xEA6D, 2)
            logger.info(f'HW Ver: {modbus_data_to_string(hw_ver_resp)}')
        # Modbus ID
        with PORT_LOCK:
            modbus_id = ntn_dongle.read_register(0xEA6F)
            logger.info(f'Modbus ID: {modbus_id}')
        # Heartbeat
        with PORT_LOCK:
            heartbeat = ntn_dongle.read_register(0xEA70)
            logger.info(f'Heartbeat: {heartbeat}')

        # NTN IMSI
        with PORT_LOCK:
            imsi_resp = ntn_dongle.read_registers(0xEB00, 8)
            logger.info(f'IMSI: {modbus_data_to_string(imsi_resp)}')
        # SINR
        with PORT_LOCK:
            sinr = ntn_dongle.read_registers(0xEB13, 2)
            logger.info(f'SINR: {modbus_data_to_string(sinr)}')
        # RSRP
        with PORT_LOCK:
            rsrp = ntn_dongle.read_registers(0xEB15, 2)
            logger.info(f'RSRP: {modbus_data_to_string(rsrp)}')
        # Latitude
        with PORT_LOCK:
            lat = ntn_dongle.read_registers(0xEB1B, 5)
            logger.info(f'Latitude: {modbus_data_to_string(lat)}')
        # Longtitude
        with PORT_LOCK:
            longi = ntn_dongle.read_registers(0xEB20, 5)
            logger.info(f'Longitude: {modbus_data_to_string(longi)}')

        """ check NTN dongle status """ 
        while True:
            with PORT_LOCK:
                # NTN module status
                ntn_status = ntn_dongle.read_register(0xEA71)
            if ntn_status:
                module_at_ready = ntn_status & 0x01
                downlink_ready = (ntn_status & 0x02) >> 1
                sim_ready = (ntn_status & 0x04) >> 2
                network_registered = (ntn_status & 0x08) >> 3

                logger.info('=== NTN dongle status ===')
                logger.info(f'module_at_ready: {module_at_ready}')
                logger.info(f'downlink_ready: {downlink_ready}')
                logger.info(f'sim_ready: {sim_ready}')
                logger.info(f'network_registered: {network_registered}')
                if ntn_status == 0xF:
                    break
            sleep(3)

        if g_args.upload:
            while True:
                data_list = []
                with PORT_LOCK:
                    # RSRP
                    rsrp_resp = ntn_dongle.read_registers(0xEB15, 2)
                if rsrp_resp:
                    logger.info(f'rsrp_resp: {rsrp_resp}')
                    rsrp = modbus_data_to_string(rsrp_resp)
                    if rsrp:
                        logger.info(f'RSRP: {repr(rsrp)}')
                        data_list.append(int(rsrp))

                with PORT_LOCK:
                    # SINR
                    sinr_resp = ntn_dongle.read_registers(0xEB13, 2)
                    logger.info(sinr_resp)
                if sinr_resp:
                    sinr = modbus_data_to_string(sinr_resp)
                    if sinr:
                        logger.info(f'SINR: {sinr}')
                        data_list.append(int(sinr))

                if data_list:
                    data = {'c':data_list}

                    d_str = json.dumps(data)
                    logger.info(f'd_str: {d_str}')
                    d_bytes = d_str.encode('utf-8')
                    logger.info(f'd_bytes: {d_bytes}')
                    d_hex  = binascii.hexlify(d_bytes)
                    logger.info(f'packet: {d_hex}')

                    modbus_data = bytes_to_list_with_padding(d_hex)
                    """ add "\r\n" in the end of data """
                    modbus_data.extend([3338])
                    logger.info(f'modbus data: {modbus_data}')

                    with PORT_LOCK:
                        # Data send
                        response = ntn_dongle.set_registers(0xC550, modbus_data)
                    logger.info(f'response: {response}')
                    if response:
                        while True:
                            with PORT_LOCK:
                                # check response length
                                data_len = ntn_dongle.read_register(0xF060)
                            if data_len != 0:
                                logger.info(f'reply data len: {data_len}')
                                """ read uplink response """
                                with PORT_LOCK:
                                    # read response data
                                    data_resp = ntn_dongle.read_registers(0xF061, data_len)
                                    logger.info(f'responsed data: {data_resp}')
                                if data_resp:
                                    uplink_resp = modbus_data_to_string(data_resp)
                                    logger.info(f'Uplink response: {uplink_resp}')
                                break
                            else:
                                sleep(1)
                """ 10 minutes routine """
                sleep(10*60)
    except Exception as e:
        logger.error(f'{e} - Code={e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
