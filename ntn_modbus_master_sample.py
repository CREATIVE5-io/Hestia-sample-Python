# === Standard Library Imports ===
import argparse
import binascii
import configparser
import csv
import json
import logging
import logging.handlers
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

# === UAV uplink sample payload ===
# Fixed field order and PDF-example default values for --ud_type uav
# (see UAV_資料格式建議_V02_20260421(Kevin).pdf, last page); --uav_data overrides a subset.
UAV_FIELD_ORDER = ['mode_id', 'landed_state', 'system_status', 'lat_e7', 'lon_e7',
                   'rel_alt_dm', 'heading_deg10', 'gspeed_dms', 'bat_voltage_cV',
                   'bat_current_cA', 'gps_fix_type', 'mission_pct']
UAV_DEFAULTS = {
    'mode_id': 5, 'landed_state': 2, 'system_status': 4,
    'lat_e7': 231067201, 'lon_e7': 1202108074, 'rel_alt_dm': 199,
    'heading_deg10': 629, 'gspeed_dms': 10, 'bat_voltage_cV': 1418,
    'bat_current_cA': 865, 'gps_fix_type': 4, 'mission_pct': 56,
}

# === nRF9151 status query commands (NTN_STATUS_SPEC.md §3) ===
# Command -> reply field names, in reply order ('!<CMD>: f1,f2,...\r\n\r\nOK\r\n').
NTN_QUERY_FIELDS = {
    'NSTATE': ['state', 'exit_reason', 'registered', 'sock_open'],
    'NCHECK': ['bitmap'],
    'NGNSS': ['fix_status', 'lat', 'lon', 'alt', 'accuracy', 'valid_until'],
    'NSIGNAL': ['rsrp', 'sinr', 'rsrq', 'band', 'earfcn', 'pci', 'cellid', 'tac'],
    'NREG': ['cereg_stat', 'ip', 'sock', 'mo_sent', 'mt_rcvd'],
    'NMO': ['queue_depth', 'queue_bytes', 'mo_sent_count', 'last_sent_ts'],
    'NTLE': ['num_sats', 'target_id', 'valid', 'dirty', 'aos', 'los'],
    'NCFG': ['apn', 'udp_ip', 'port', 'bind', 'pdp'],
    'NVER': ['app_version', 'zephyr', 'modem_fw', 'provider'],
    'NERR': ['exit_reason', 'ceer', 'fail_cnt', 'rrc_idle'],
}
# NCHECK bitmap bit -> meaning
NCHECK_BITS = ['module_ready', 'sim_ready', 'provider_resolved', 'gnss_fix_valid',
               'tle_valid', 'ntn_registered', 'socket_open', 'mo_queue_pending']

# === Argument Parsing ===
def parse_arguments():
    parser = argparse.ArgumentParser(description="NTN-MODBUS-MASTER-TEST")
    parser.add_argument("--type", type=str, help="Specify NIDD or UDP (default: UDP)", default='UDP')
    parser.add_argument("--port", type=str, help="Specify port (default: /dev/ttyUSB0)", default='/dev/ttyUSB0')
    parser.add_argument("--upload", action='store_true', help="Enable upload test (default: False)", default=False)
    parser.add_argument("--ud_type", type=str, choices=['signal', 'gps', 'uav', 'all'], default='all',
                        help="Upload data type: 'signal' for RSRP/SINR, 'gps' for lat/long, "
                             "'uav' for a MAVLink-derived UAV telemetry sample, 'all' for signal+gps (default: all)")
    parser.add_argument("--ud_data", type=str, default=None,
                        help="Raw upload data string sent as-is; overrides --ud_type and implies --upload (default: None)")
    parser.add_argument("--uav_data", type=str, default=None,
                        help="JSON object overriding uav fields (mode_id, landed_state, system_status, lat_e7, "
                             "lon_e7, rel_alt_dm, heading_deg10, gspeed_dms, bat_voltage_cV, bat_current_cA, "
                             "gps_fix_type, mission_pct, ts_unix_s); unspecified fields use sample defaults "
                             "(default: None)")
    parser.add_argument("--ud_size", type=int, default=0,
                        help="Pad upload payload to this many bytes with '1234567890' fill (0=no padding, default: 0)")
    parser.add_argument("--ud_fill", action='store_true', default=False,
                        help="Send exactly --ud_size bytes of repeating '1234567890', no other data; implies --upload")
    parser.add_argument("--no_ack", action='store_true', default=False,
                        help="Dongle firmware does not send an uplink ACK; skip waiting on 0xF060/0xF061 after upload (default: False, waits for ACK)")
    parser.add_argument("--dl", action='store_true', help="Enable downlink test (default: False)", default=False)
    parser.add_argument("--interval", type=int, help="Status loop interval in seconds (default: 600)", default=600)
    # UDP device config
    parser.add_argument("--ntn_config", action='store_true', help="Configure NTN dongle UDP parameters, ONLY use this config in UDP version dongle firmware", default=False)
    parser.add_argument("--remote_port", type=str, help="Specify remote port", default='')
    parser.add_argument("--apn", type=str, help="Specify APN", default='')
    parser.add_argument("--ip", type=str, help="Specify remote IP", default='')
    parser.add_argument("--local_port", type=str, help="Specify local port", default='')
    # NTN/TN module command channel (0x9C40, Nordic nRF9151 modem only)
    parser.add_argument("--network_registration_status", action='store_true', default=False,
                        help="Nordic nRF9151 modem only. One-shot: query network registration status "
                             "(AT+CEREG?) via the NTN/TN module command channel (0x9C40), then exit")
    parser.add_argument("--leo_config", action='store_true', default=False,
                        help="Nordic nRF9151 modem only. Configure LEO target satellite (SET_TARGET_ID) "
                             "and orbit (SET_TLE) via 0x9C40; requires --tle_file")
    parser.add_argument("--tle_file", type=str, default=None,
                        help="3-line TLE file (SATELIOT_<id> name, TLE line1, TLE line2) for --leo_config")
    parser.add_argument("--ntn_trigger", type=str, choices=['sgp4', 'gnss', 'tn', 'ntn'], default=None,
                        help="Nordic nRF9151 modem only. Trigger network mode via 0x9C40: 'sgp4'=LEO "
                             "tracking, 'gnss'=GNSS fix, 'tn'=terrestrial, 'ntn'=GEO satellite. Before "
                             "triggering 'ntn', trigger 'gnss' first and confirm the GPS location "
                             "(0xEB1B/0xEB20) has updated")
    parser.add_argument("--ntn_query", type=str.upper, nargs='+', choices=list(NTN_QUERY_FIELDS) + ['ALL'],
                        default=None, metavar='CMD',
                        help="Nordic nRF9151 modem only. Send status query command(s) via 0x9C40 "
                             "(NTN_STATUS_SPEC §3) each status loop iteration, before uplink, and log "
                             "the parsed replies. "
                             f"Choices (case-insensitive): {', '.join(NTN_QUERY_FIELDS)}, ALL")
    parser.add_argument("--ntn_query_once", action='store_true', default=False,
                        help="With --ntn_query: one-shot mode, run the queries once and exit "
                             "instead of each status loop iteration")
    # LoRa (A2 hardware)
    parser.add_argument("--lora", action='store_true', help="Enable LoRa data polling in status loop (default: False)", default=False)
    parser.add_argument("--lora_setup", action='store_true', help="Enable LoRa module setup", default=False)
    parser.add_argument("--lora_node_query", action='store_true', help="Query LoRa node keys (private + OTAA EUI)", default=False)
    parser.add_argument("--lora_node_setup", action='store_true', help="Setup LoRa node keys (private + OTAA EUI) from lora.ini", default=False)
    parser.add_argument("--lora_node_cleanup", action='store_true', help="Cleanup all LoRa node keys (private + OTAA EUI)", default=False)
    parser.add_argument("--lora_pubkey_setup", action='store_true', help="Setup LoRa public key from lora.ini", default=False)
    parser.add_argument("--lora_pubkey_cleanup", action='store_true', help="Cleanup LoRa public key", default=False)
    parser.add_argument("--log_file", type=str, default='ntn_modbus.log',
                        help="Log file path (default: ntn_modbus.log); set to '' to disable file logging")
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
            self.lora_fmt = None
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

    def set_register(self, reg, val):
        with self.lock:
            try:
                if val is not None:
                    self.master.execute(self.slaveAddr, cst.WRITE_SINGLE_REGISTER, reg, output_value=val)
                    return True
                else:
                    return False
            except Exception as e:
                logger.info(e)
                return False

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

    def ntn_cmd(self, cmd):
        """Write an ASCII command + CRLF to the NTN/TN module command channel (0x9C40)."""
        ascii_cmd = self._at_command_to_ascii(cmd + '\r\n')
        return self.set_registers(0x9C40, ascii_cmd)

    def get_lora_fmt(self):
        """Query the LoRa BIS format (AT+BISFMT=?), cache it, and return it as an int."""
        data = self.pcie2_cmd('AT+BISFMT=?')
        if not data:
            return None
        try:
            self.lora_fmt = int(re.split(r'[:\s\n]+', data)[2])
        except (IndexError, ValueError):
            return None
        return self.lora_fmt

    def pcie2_cmd(self, cmd):
        """Send an AT command to the PCIe2 (LoRa) module and return the decoded response."""
        if cmd == 'AT+BISGET=?':
            if self.lora_fmt is None:
                self.get_lora_fmt()
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
                if self.lora_fmt == 1:
                    idx_1st = a_codes.index(34)
                    idx_2nd = a_codes.index(34, idx_1st + 1)
                    a_codes = a_codes[idx_1st + 1:idx_2nd]
                logger.debug(f'a_codes: {a_codes}')
                try:
                    return binascii.unhexlify(bytes(a_codes)).decode('utf8')
                except binascii.Error:
                    pass
                return bytes(a_codes).decode('utf8')
            else:
                logger.debug(f'a_codes: {a_codes}')
                return bytes(a_codes).decode('utf8')
        except Exception as e:
            logger.info(e)
            return None


def dl_read(ntn_dongle):
    """Continuously read downlink data from the device (runs in a daemon thread)."""
    MAX_REGS_PER_READ = 64  # match NTN downlink data part size (EC61–ECA0)
    while True:
        try:
            data_len = 0
            error = False
            data_len = ntn_dongle.read_register(0xEC60)
            if data_len != 0:
                logger.info(f'Downlink data length: {data_len}')
                dl_resp = []
                addr = 0xEC61
                remaining = data_len
                while remaining > 0:
                    chunk = min(remaining, MAX_REGS_PER_READ)
                    regs = ntn_dongle.read_registers(addr, chunk)
                    if regs == None:
                        error = True
                        break
                    dl_resp.extend(regs)
                    addr += chunk
                    remaining -= chunk
                if not error:
                    logger.info(f'Downlink data response: {dl_resp}')
                    dl_data = b''.join(struct.pack('>H', v) for v in dl_resp)
                    try:
                        dl_text = binascii.unhexlify(dl_data).decode('utf-8').rstrip('\x00')
                    except Exception:
                        dl_text = dl_data.decode('utf-8', errors='replace').rstrip('\x00')
                    try:
                        dl_data = json.loads(dl_text)
                        logger.info(f'Downlink data (JSON): {dl_data}')
                    except json.JSONDecodeError:
                        logger.info(f'Downlink data (text): {dl_text}')
                sleep(1)
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

    def get_private_keys(self):
        section = 'PRIVATE_KEY' if 'PRIVATE_KEY' in self.config else 'DEVICES'
        return dict(self.config[section]) if section in self.config else {}

    def get_pubkey(self):
        if 'PUBLIC_KEY' in self.config and 'pubkey' in self.config['PUBLIC_KEY']:
            return self.config['PUBLIC_KEY']['pubkey']
        return None

    def get_otaa_eui(self):
        return dict(self.config['OTAA_EUI']) if 'OTAA_EUI' in self.config else {}


def ntn_cmd_reply(ntn_dongle, timeout_s=5):
    """Poll 0xF060 (reply length) then read 0xF061 (reply data) after an
    NTN/TN command-channel (0x9C40) write; same reply registers as uplink."""
    deadline = time() + timeout_s
    while time() < deadline:
        data_len = ntn_dongle.read_register(0xF060)
        if data_len:
            data_resp = ntn_dongle.read_registers(0xF061, data_len)
            return ntn_modbus_master.modbus_data_to_string(data_resp) if data_resp else None
        sleep(1)
    return None


SATELIOT_NAME_RE = re.compile(r'^SATELIOT_(\d+)$', re.IGNORECASE)


def parse_tle_file(path):
    """Parse a 3-line TLE file (name, line1, line2) for --leo_config.
    Target ID is parsed from the name; only 'SATELIOT_<id>' is supported."""
    with open(path, encoding='ascii', errors='replace') as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if len(lines) < 3:
        raise ValueError(f'TLE file requires at least 3 lines (name + line1 + line2), got {len(lines)}')
    name, line1, line2 = lines[0], lines[1], lines[2]
    m = SATELIOT_NAME_RE.match(name)
    if not m:
        raise ValueError(f"Unsupported satellite name '{name}': only 'SATELIOT_<id>' is currently supported")
    return int(m.group(1)), name, line1, line2


def _ntn_cmd_unlock(ntn_dongle):
    """Write the default password (Sequence 1 unlock), matching ntn_config()/ntn_info()."""
    DEFAULT_PASSWD = '00000000'
    passwd = [int(DEFAULT_PASSWD[i:i+2]) for i in range(0, len(DEFAULT_PASSWD), 2)]
    if not ntn_dongle.set_registers(0x0000, passwd):
        logger.error('Password set failed')
        return False
    return True


def network_registration_status(ntn_dongle):
    """One-shot: AT+CEREG? via the NTN/TN module command channel (0x9C40), log the reply."""
    if not _ntn_cmd_unlock(ntn_dongle):
        return
    if not ntn_dongle.ntn_cmd('AT+CEREG?'):
        logger.error('AT+CEREG? command failed')
        return
    reply = ntn_cmd_reply(ntn_dongle)
    logger.info(f'Network registration status: {reply}')


def leo_config(ntn_dongle, tle_file):
    """Parse --tle_file, then SET_TARGET_ID + SET_TLE over the 0x9C40 command channel."""
    try:
        target_id, name, line1, line2 = parse_tle_file(tle_file)
    except (OSError, ValueError) as e:
        logger.error(f'--leo_config failed: {e}')
        return
    if not _ntn_cmd_unlock(ntn_dongle):
        return
    if not ntn_dongle.ntn_cmd(f'SET_TARGET_ID {target_id}'):
        logger.error('SET_TARGET_ID failed')
        return
    logger.info(f'SET_TARGET_ID {target_id} sent')
    if not ntn_dongle.ntn_cmd(f'SET_TLE "{name}" "{line1}" "{line2}"'):
        logger.error('SET_TLE failed')
        return
    logger.info(f'SET_TLE "{name}" sent')


def ntn_trigger(ntn_dongle, which):
    """Trigger LEO(sgp4) / GNSS / TN / GEO(ntn) mode via the 0x9C40 command channel."""
    cmd_map = {'sgp4': 'SGP4_TRIGGER', 'gnss': 'GNSS_TRIGGER', 'tn': 'TN_TRIGGER', 'ntn': 'NTN_TRIGGER'}
    cmd = cmd_map[which]
    if not _ntn_cmd_unlock(ntn_dongle):
        return
    if ntn_dongle.ntn_cmd(cmd):
        logger.info(f'{cmd} sent')
    else:
        logger.error(f'{cmd} failed')


def parse_ntn_query_reply(cmd, reply):
    """Parse '!<CMD>: v1,v2,...\r\n\r\nOK\r\n' into {field: value}.
    Returns 'NONE' for a no-data reply, None if the reply is missing/ERROR/unrecognized."""
    if not reply:
        return None
    m = re.search(rf'!{cmd}:\s*(.*?)\s*(?:\r?\n|$)', reply)
    if not m:
        return None
    body = m.group(1)
    if body == 'NONE':
        return 'NONE'
    values = next(csv.reader([body], skipinitialspace=True))
    fields = NTN_QUERY_FIELDS[cmd]
    if len(values) != len(fields):
        logger.warning(f'{cmd}: expected {len(fields)} fields, got {len(values)}: {values}')
    parsed = dict(zip(fields, values))
    if cmd == 'NCHECK' and 'bitmap' in parsed:
        try:
            bits = int(parsed['bitmap'], 16)
            parsed.update({name: (bits >> i) & 1 for i, name in enumerate(NCHECK_BITS)})
        except ValueError:
            pass
    return parsed


def ntn_query(ntn_dongle, cmds):
    """Send NTN_STATUS_SPEC §3 query command(s) via 0x9C40, log raw + parsed replies.
    Called once from main() with --ntn_query_once, else from ntn_status_loop() before uplink, since replies share 0xF060/0xF061 with the uplink ACK."""
    if 'ALL' in cmds:
        cmds = list(NTN_QUERY_FIELDS)
    if not _ntn_cmd_unlock(ntn_dongle):
        return
    for cmd in dict.fromkeys(cmds):
        if not ntn_dongle.ntn_cmd(cmd):
            logger.error(f'{cmd} command failed')
            continue
        reply = ntn_cmd_reply(ntn_dongle)
        logger.info(f'{cmd} reply: {reply!r}')
        parsed = parse_ntn_query_reply(cmd, reply)
        if parsed is None:
            logger.error(f'{cmd}: no valid reply')
        else:
            logger.info(f'{cmd}: {parsed}')


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
        else:
            logger.info(f'{desc}: {resp}')

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
    fw_ver = get_lora_fw_ver(ntn_dongle)
    otaa_supported = fw_ver is not None and _ver_tuple(fw_ver) >= (1, 3, 0)
    node_count = get_max_node_count(fw_ver)
    logger.info(f'LoRa FW version: {fw_ver}, OTAA supported: {otaa_supported}, node count: {node_count}')
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

    if args.lora_node_setup:
        devices = lora_conf.get_private_keys()
        otaa = lora_conf.get_otaa_eui()
        logger.info(f'LoRa devices: {devices}')
        logger.info(f'LoRa OTAA EUI: {otaa}')
        # Build a lookup from index string to OTAA value
        otaa_by_index = {}
        for v in otaa.values():
            parts = v.split(':', 1)
            if parts:
                otaa_by_index[parts[0]] = v
        for k, v in devices.items():
            index = v.split(':')[0]
            if int(index) >= node_count:
                logger.warning(f'Skipping index {index}: exceeds max node count {node_count} for FW {fw_ver}')
                continue
            logger.debug(f'AT+BISDEV={v}')
            data = ntn_dongle.pcie2_cmd('AT+BISDEV=' + v)
            logger.debug(f'response: {data}')
            if index in otaa_by_index:
                if otaa_supported:
                    otaa_cmd = 'AT+BISOTAA=' + otaa_by_index[index]
                    logger.debug(otaa_cmd)
                    data = ntn_dongle.pcie2_cmd(otaa_cmd)
                    logger.debug(f'response: {data}')
                else:
                    logger.warning(f'Skipping OTAA for index {index}: FW {fw_ver} < V1.3.0')

    if args.lora_node_cleanup:
        for i in range(node_count):
            cmd = f'AT+BISDEV={i}:ffffffff:ffffffffffffffffffffffffffffffff:ffffffffffffffffffffffffffffffff'
            data = ntn_dongle.pcie2_cmd(cmd)
            logger.info(f'response: {data}')
            if otaa_supported:
                cmd = f'AT+BISOTAA={i}:ffffffffffffffff:ffffffffffffffff:ffffffffffffffffffffffffffffffff'
                data = ntn_dongle.pcie2_cmd(cmd)
                logger.info(f'response: {data}')
            else:
                logger.warning(f'Skipping OTAA cleanup for slot {i}: FW {fw_ver} < V1.3.0')

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


def get_lora_fw_ver(ntn_dongle):
    """Query LoRa module firmware version via AT+VER=? and return the version string."""
    data = ntn_dongle.pcie2_cmd('AT+VER=?')
    if not data:
        return None
    return next((line.strip() for line in data.splitlines() if line.strip() and line.strip() != 'OK'), None)


def _ver_tuple(ver_str):
    """Parse version string like 'V1.3.0' into a comparable tuple (1, 3, 0)."""
    try:
        return tuple(int(x) for x in ver_str.lstrip('Vv').split('.'))
    except (ValueError, AttributeError):
        return (0, 0, 0)


def get_max_node_count(ver_str):
    """31 nodes (slots 0-30) for FW >= V1.3.2, else 16 nodes (slots 0-15)."""
    return 31 if ver_str is not None and _ver_tuple(ver_str) >= (1, 3, 2) else 16


def lora_node_query(ntn_dongle):
    """Query and log LoRa node keys (private keys and OTAA EUI) for all supported slots
    (31 slots for FW >= V1.3.2, else 16 slots)."""
    version = get_lora_fw_ver(ntn_dongle)
    if version:
        logger.info(f'LoRa module version: {version}')
    else:
        logger.error('LoRa version query failed')

    otaa_supported = version is not None and _ver_tuple(version) >= (1, 3, 0)
    node_count = get_max_node_count(version)
    logger.info(f'Max node count: {node_count}')
    for i in range(node_count):
        cmd = f'AT+BISDEV={i}?'
        data = ntn_dongle.pcie2_cmd(cmd)
        if data:
            logger.info(f'Lora device {i}: {data}')
        else:
            logger.error(f'Lora device {i} query failed')
        if otaa_supported:
            cmd = f'AT+BISOTAA={i}?'
            data = ntn_dongle.pcie2_cmd(cmd)
            if data:
                logger.info(f'Lora OTAA {i}: {data}')
            else:
                logger.error(f'Lora OTAA {i} query failed')
        else:
            logger.warning(f'Skipping OTAA query for slot {i}: FW {version} < V1.3.0')


def ntn_status_loop(ntn_dongle, args, lora_conf):
    """Main status loop: poll NTN status, run --ntn_query, upload telemetry, poll LoRa, then sleep --interval seconds.
    The interval is wall-clock based: sleep time = interval - elapsed work time."""
    while True:
        t_start = time()
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

        # nRF9151 status queries (0x9C40); must finish before uplink, which reuses 0xF060/0xF061
        if args.ntn_query:
            logger.info('=== nRF9151 status query ===')
            ntn_query(ntn_dongle, args.ntn_query)

        avbl = ntn_dongle.read_register(0xEA7D)
        logger.info(f'{avbl=}')
        upload_avbl = ntn_dongle.read_register(0xEA7D) == 0

        do_upload = args.upload or (args.ud_data is not None) or args.ud_fill
        if net_status and upload_avbl:
            if do_upload:
                if args.ud_fill:
                    # Fill path: send exactly ud_size bytes of repeating '1234567890'
                    fill = b'1234567890'
                    size = args.ud_size if args.ud_size > 0 else 150
                    d_bytes = (fill * (size // len(fill) + 1))[:size]
                    logger.info(f'd_bytes ({len(d_bytes)}B): {d_bytes}')
                    d_hex = binascii.hexlify(d_bytes)
                    logger.info(f'packet: {d_hex}')
                    d_hex += b'\r\n'
                    modbus_data = ntn_modbus_master.bytes_to_list_with_padding(d_hex)
                    logger.info(f'modbus data: {modbus_data}')
                    MAX_REGS_PER_WRITE = 64
                    response = False
                    for i in range(0, len(modbus_data), MAX_REGS_PER_WRITE):
                        chunk = modbus_data[i:i + MAX_REGS_PER_WRITE]
                        response = ntn_dongle.set_registers(0xC550 + i, chunk)
                        if not response:
                            break
                    logger.info(f'response: {response}')
                    if response and not args.no_ack:
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
                elif args.ud_data is not None:
                    # Raw data path: send --ud_data string directly, ignore --ud_type
                    raw_packets = [args.ud_data]
                    is_raw = True
                else:
                    # Register read path: assemble packets from device registers per --ud_type
                    raw_packets = []
                    is_raw = False

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
                            raw_packets.append({'c': signal_list})

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
                            raw_packets.append({'g': gps_list})

                    if args.ud_type == 'uav':
                        uav_fields = dict(UAV_DEFAULTS)
                        ts_override = None
                        if args.uav_data:
                            try:
                                overrides = json.loads(args.uav_data)
                                ts_override = overrides.pop('ts_unix_s', None)
                                uav_fields.update(overrides)
                            except json.JSONDecodeError as e:
                                logger.error(f'Invalid --uav_data JSON: {e}')
                        ts_unix_s = ts_override if ts_override is not None else int(time())
                        uav_values = [ts_unix_s] + [uav_fields[f] for f in UAV_FIELD_ORDER]
                        raw_packets.append({'D': [{'mv': ['uav'] + uav_values}]})

                if not args.ud_fill:
                    for data in raw_packets:
                        if is_raw:
                            d_bytes = data.encode('utf-8')
                        else:
                            d_str = json.dumps(data)
                            logger.info(f'd_str: {d_str}')
                            d_bytes = d_str.encode('utf-8')
                        if args.ud_size > 0:
                            if len(d_bytes) < args.ud_size:
                                fill = b'1234567890'
                                needed = args.ud_size - len(d_bytes)
                                d_bytes = d_bytes + (fill * (needed // len(fill) + 1))[:needed]
                            elif len(d_bytes) > args.ud_size:
                                logger.warning(f'Upload data ({len(d_bytes)}B) exceeds --ud_size {args.ud_size}B')
                        logger.info(f'd_bytes ({len(d_bytes)}B): {d_bytes}')
                        d_hex = binascii.hexlify(d_bytes)
                        logger.info(f'packet: {d_hex}')
                        d_hex += b'\r\n'
                        modbus_data = ntn_modbus_master.bytes_to_list_with_padding(d_hex)
                        logger.info(f'modbus data: {modbus_data}')
                        MAX_REGS_PER_WRITE = 64  # match NTN uplink data part size (C550–C58F)
                        response = False
                        for i in range(0, len(modbus_data), MAX_REGS_PER_WRITE):
                            chunk = modbus_data[i:i + MAX_REGS_PER_WRITE]
                            response = ntn_dongle.set_registers(0xC550 + i, chunk)
                            if not response:
                                break
                        logger.info(f'response: {response}')
                        if response and not args.no_ack:
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
            devices = lora_conf.get_private_keys()
            for i in range(len(devices)):
                data = ntn_dongle.pcie2_cmd('AT+BISGET=?')
                logger.info(f'{data=}')

        elapsed = time() - t_start
        wait = max(0, args.interval - elapsed)
        logger.info(f'Loop done in {elapsed:.1f}s, sleeping {wait:.1f}s (interval={args.interval}s)')
        sleep(wait)


def main():
    args = parse_arguments()
    if args.log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s    %(levelname)-8s %(name)s    %(threadName)s    %(message)s'))
        logger.addHandler(file_handler)
        logger.info(f'Logging to file: {args.log_file}')
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
        # One-shot network registration status query (AT+CEREG? via 0x9C40)
        if args.network_registration_status:
            network_registration_status(ntn_dongle)
            return
        # One-shot nRF9151 status query (--ntn_query --ntn_query_once)
        if args.ntn_query_once:
            if not args.ntn_query:
                logger.error('Please provide --ntn_query for --ntn_query_once.')
                sys.exit(1)
            ntn_query(ntn_dongle, args.ntn_query)
            return
        ntn_info(ntn_dongle, args)
        # LoRa setup (A2 hardware)
        if any([args.lora_setup, args.lora_node_cleanup, args.lora_node_setup,
                args.lora_pubkey_setup, args.lora_pubkey_cleanup]):
            setup_lora(ntn_dongle, lora_conf, args)
        if args.lora_node_query:
            lora_node_query(ntn_dongle)
        # LEO target/orbit config and network mode trigger (0x9C40, nRF9151 firmware)
        if args.leo_config:
            if not args.tle_file:
                logger.error('Please provide --tle_file for --leo_config.')
                sys.exit(1)
            leo_config(ntn_dongle, args.tle_file)
        if args.ntn_trigger:
            ntn_trigger(ntn_dongle, args.ntn_trigger)
        ntn_status_loop(ntn_dongle, args, lora_conf)
    except Exception as e:
        logger.error(f'{e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
