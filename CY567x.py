"""
manages two cypress dongles: CY5677 and CY5670 (old)
"""
import datetime
import queue
import struct
import threading

import serial

import cycost as cc
import cyproto as prt
import utili
from scan_util import scan_report, scan_advertise, ba_from_stringuuid, stringuuid_from_ba

BAUD_CY5670 = 115200
BAUD_CY5677 = 921600

IO_CAPABILITIES = {
    # Platform supports only a mechanism to display or convey only 6 digit
    # number to user.
    'DISPLAY ONLY': 0,

    # The device has a mechanism whereby the user can indicate 'yes' or 'no'.
    'DISPLAY YESNO': 1,

    # Platform supports a numeric keyboard that can input the numbers '0' through '9'
    # and a confirmation key(s) for 'yes' and 'no'.
    'KEYBOARD ONLY': 2,

    # Platform does not have the ability to display or communicate a 6 digit decimal number.
    'NOINPUT NOOUTPUT': 3,

    # Platform supports a mechanism through which 6 digit numeric value can be displayed
    # and numeric keyboard that can input the numbers '0' through '9'.
    'KEYBOARD DISPLAY': 4,
}


def valore(cosa, diz):
    for k, v in diz.items():
        if v == cosa:
            return k
    return 0


ADDRESS_TYPE = {
    0: 'PUBLIC',
    1: 'RANDOM',
    2: 'PUBLIC RPA',
    3: 'RANDOM RPA'
}


def desc_at(at):
    try:
        return ADDRESS_TYPE[at]
    except KeyError:
        return 'ADDRESS TYPE ? {} ?'.format(at)


FILTER_POLICY = {
    0: 'CYBLE_GAPC_ADV_ACCEPT_ALL_PKT',
    1: 'CYBLE_GAPC_ADV_ACCEPT_WHITELIST_PKT',
    2: 'CYBLE_GAPC_ADV_ACCEPT_DIRECTED_RPA_PKT',
    3: 'CYBLE_GAPC_ADV_ACCEPT_WHITELIST_DIRECTED_RPA_PKT'
}


def desc_fp(fp):
    try:
        return FILTER_POLICY[fp]
    except KeyError:
        return 'FILTER POLICY ? {} ?'.format(fp)


DISCOVERY_PROC = {
    0: 'Observation',
    1: 'Limited discovery',
    2: 'General discovery'
}


def desc_dp(dp):
    try:
        return DISCOVERY_PROC[dp]
    except KeyError:
        return 'DISCOVERY PROC ? {} ?'.format(dp)


# CYBLE_BLESS_PWR_LVL_T will be the index + 1
TX_POW_DBM = [-18, -12, -6, -3, -2, -1, 0, 3]


def val_tp(dbm):
    """
    convert a power to a valid enum

    :param dbm: power
    :return: CYBLE_BLESS_PWR_LVL_T
    """
    pl = None
    try:
        pl = 1 + TX_POW_DBM.index(dbm)
    except ValueError:
        for elem in TX_POW_DBM:
            if elem > dbm:
                pl = 1 + TX_POW_DBM.index(elem)
                break
    if pl is None:
        pl = len(TX_POW_DBM)
    return pl


def desc_tp(tp):
    """
    convert enum to a string

    :param tp: CYBLE_BLESS_PWR_LVL_T
    :return: string
    """
    if tp <= len(TX_POW_DBM):
        return '{} dBm'.format(TX_POW_DBM[tp - 1])

    return 'TX POWER ? {} ?'.format(tp)


class _COMMAND:
    def __init__(self, cmd, prm=None):
        self._cod = cmd
        self._prm = prm
        self._res_q = queue.Queue()
        self._depot = None

    def are_you(self, cmd):
        """
        compare the command codes
        :param cmd: command code
        :return: bool
        """
        return self._cod == cmd

    def get(self):
        """
        retrieves the command's parameters
        :return:
        """
        return {'cod': self._cod, 'prm': self._prm}

    def get_result(self, to=5):
        """
        wait for and return the result
        :param to: timeout in seconds
        :return: the result or None if to expires
        """
        try:
            return self._res_q.get(True, to)
        except queue.Empty:
            return None

    def set_result(self, res):
        """
        put the result in the queue
        :param res: the command's result
        :return: n.a.
        """
        if self._depot is None:
            self._res_q.put_nowait(res)
        else:
            self._res_q.put_nowait(self._depot)

    def save(self, data):
        """
        save a result
        :param data: bytearray
        :return:
        """
        if self._depot is None:
            self._depot = bytearray(data)
        else:
            self._depot += bytearray(data)


class CY567x(threading.Thread):
    """
    manages two cypress dongles: CY5677 and CY5670 (old)
    """
    # internal commands
    QUIT = 0xE5C1
    ABORT_CURRENT_COMMAND = 0xACC0
    # 3 bits group + 7 bits id
    GENERAL_GROUP = 0 << 7
    L2CAP_GROUP = 2 << 7
    GATT_GROUP = 4 << 7
    GAP_GROUP = 5 << 7
    # dongle commands (cfr CySmt_CommandLayer.c)
    Cmd_Init_Ble_Stack_Api = 0xFC07
    Cmd_Get_Rssi_Api = GENERAL_GROUP + 13
    Cmd_Get_TxPowerLevel_Api = GENERAL_GROUP + 14
    Cmd_Set_TxPowerLevel_Api = GENERAL_GROUP + 15
    Cmd_Get_Bluetooth_Device_Address_Api = 0xFE82
    Cmd_Get_Scan_Parameters_Api = 0xFE8A
    Cmd_Set_Scan_Parameters_Api = 0xFE8B
    Cmd_Start_Scan_Api = 0xFE93
    Cmd_Stop_Scan_Api = 0xFE94
    Cmd_Set_Local_Device_Security_Api = 0xFE8D
    Cmd_Set_Device_Io_Capabilities_Api = 0xFE80
    Cmd_Establish_Connection_Api = 0xFE97
    Cmd_Exchange_GATT_MTU_Size_Api = 0xFE12
    Cmd_Initiate_Pairing_Request_Api = 0xFE99
    Cmd_Pairing_PassKey_Api = 0xFE9B
    Cmd_Terminate_Connection_Api = 0xFE98
    Cmd_Characteristic_Value_Write_Without_Response_Api = GATT_GROUP + 10
    Cmd_Write_Characteristic_Value_Api = GATT_GROUP + 11
    Cmd_Write_Long_Characteristic_Value_Api = GATT_GROUP + 12
    Cmd_Write_Characteristic_Descriptor_Api = GATT_GROUP + 16
    Cmd_Read_Characteristic_Value_Api = 0xFE06
    Cmd_Read_Long_Characteristic_Values_Api = 0xFE08
    Cmd_Read_Characteristic_Descriptor_Api = 0xFE0E
    Cmd_Tool_Disconnected_Api = 0xFC08
    Cmd_Discover_Primary_Services_By_Uuid_Api = 0xFE01
    Cmd_Discover_All_Primary_Services_Api = 0xFE00
    Cmd_Discover_Characteristics_By_Uuid_Api = 0xFE04
    Cmd_Discover_All_Characteristics_Api = 0xFE03
    Cmd_Discover_All_Characteristic_Descriptors_Api = 0xFE05

    def __init__(self, BAUD=BAUD_CY5677, poll=0.1, porta=None):
        self._can_print = False
        #self._can_print = True

        self.proto = {'rx': prt.PROTO_RX(), 'tx': prt.PROTO_TX()}

        self.events = {
            cc.EVT_COMMAND_STATUS:
            self._evt_command_status,
            cc.EVT_COMMAND_COMPLETE:
            self._evt_command_complete,
            cc.EVT_SCAN_PROGRESS_RESULT:
            self._evt_scan_progress_result,
            cc.EVT_ESTABLISH_CONNECTION_RESPONSE:
            self._evt_gatt_connect_ind,
            cc.EVT_ENHANCED_CONNECTION_COMPLETE:
            self._evt_gap_enhance_conn_complete,
            cc.EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION:
            self._evt_gap_auth_req,
            cc.EVT_DATA_LENGTH_CHANGED_NOTIFICATION:
            self._evt_gap_data_length_change,
            cc.EVT_NEGOTIATED_PAIRING_PARAMETERS:
            self._evt_negotiated_pairing_parameters,
            cc.EVT_PASSKEY_ENTRY_REQUEST:
            self._evt_gap_passkey_entry_request,
            cc.EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE:
            self._evt_gattc_xchng_mtu_rsp,
            cc.EVT_AUTHENTICATION_ERROR_NOTIFICATION:
            self._evt_gap_auth_failed,
            cc.EVT_CONNECTION_TERMINATED_NOTIFICATION:
            self._evt_gap_device_disconnected,
            cc.EVT_REPORT_STACK_MISC_STATUS:
            self._evt_report_stack_misc_status,
            cc.EVT_CHARACTERISTIC_VALUE_NOTIFICATION:
            self._evt_gattc_handle_value_ntf,
            cc.EVT_CHARACTERISTIC_VALUE_INDICATION:
            self._evt_gattc_handle_value_ind,
            cc.EVT_GET_BLUETOOTH_DEVICE_ADDRESS_RESPONSE:
            self._evt_get_bluetooth_device_address_response,
            cc.EVT_SCAN_STOPPED_NOTIFICATION:
            self._evt_scan_stopped_notification,
            cc.EVT_GATT_ERROR_NOTIFICATION:
            self._evt_gatt_error_notification,
            cc.EVT_READ_CHARACTERISTIC_VALUE_RESPONSE:
            self._evt_gattc_read_rsp,
            cc.EVT_READ_LONG_CHARACTERISTIC_VALUE_RESPONSE:
            self._evt_gattc_read_rsp,
            cc.EVT_DISCOVER_PRIMARY_SERVICES_BY_UUID_RESULT_PROGRESS:
            self._evt_gattc_find_by_type_value_rsp,
            cc.EVT_DISCOVER_ALL_PRIMARY_SERVICES_RESULT_PROGRESS:
            self._evt_gattc_read_by_group_type_rsp,
            cc.EVT_DISCOVER_CHARACTERISTICS_BY_UUID_RESULT_PROGRESS:
            self._evt_gattc_read_by_type_rsp_chr_uid,
            cc.EVT_DISCOVER_ALL_CHARACTERISTICS_RESULT_PROGRESS:
            self._evt_gattc_read_by_type_rsp_all_char,
            cc.EVT_DISCOVER_ALL_CHARACTERISTIC_DESCRIPTORS_RESULT_PROGRESS:
            self._evt_gattc_find_info_rsp,
            cc.EVT_READ_CHARACTERISTIC_DESCRIPTOR_RESPONSE:
            self._evt_gattc_read_rsp,
            cc.EVT_GET_SCAN_PARAMETERS_RESPONSE:
            self._evt_get_scan_parameters_response,
            cc.EVT_GET_TX_POWER_RESPONSE:
            self._evt_get_tx_power_response,
            cc.EVT_GET_RSSI_RESPONSE:
            self._evt_get_rssi_response
        }

        self.connection = {'mtu': 23, 'cyBle_connHandle': None}

        self.command = {
            'curr': None,
            'todo': queue.Queue(),
            'poll': poll,
        }

        self.services = {'primary': [], 'current': [], 'char': []}

        try:
            serial_open = serial.Serial
            if porta is None:
                porta = 'hwgrep://04B4:F139'
                serial_open = serial.serial_for_url

            self.uart = serial_open(porta,
                                    baudrate=BAUD,
                                    bytesize=serial.EIGHTBITS,
                                    parity=serial.PARITY_NONE,
                                    stopbits=serial.STOPBITS_ONE,
                                    timeout=1,
                                    rtscts=True)

            # posso girare
            threading.Thread.__init__(self, daemon=True)
            self.start()

        except serial.SerialException as err:
            self._print(str(err))
            self.uart = None

    def __del__(self):
        self._print('del')
        self.close()

    def _print(self, msg):
        if self._can_print:
            adesso = datetime.datetime.now()
            sadesso = '{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03.0f}: '.format(
                adesso.year, adesso.month, adesso.day, adesso.hour,
                adesso.minute, adesso.second, adesso.microsecond / 1000.0)

            print(sadesso + msg)

    def _close_command(self, cod, resul):
        if self.command['curr'] is None:
            self._print('no cmd waiting')
        elif self.command['curr'].are_you(cod):
            self.command['curr'].set_result(resul == 0)
            self.command['curr'] = None
        else:
            self._print('wrong cmd')

    def _save_data(self, cod, data):
        if self.command['curr'] is None:
            self._print('_save_data: no cmd waiting')
        elif self.command['curr'].are_you(cod):
            self.command['curr'].save(data)
        else:
            self._print('_save_data: wrong cmd {:04X}'.format(cod))

    def _evt_command_status(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        self._print('EVT_COMMAND_STATUS: cmd={:04X} stt={}'.format(
            cmd, status))
        if cmd in (self.Cmd_Start_Scan_Api,
                   self.Cmd_Initiate_Pairing_Request_Api):
            self._close_command(cmd, status)

    def _evt_command_complete(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        self._print('EVT_COMMAND_COMPLETE: cmd={:04X} stt={}'.format(
            cmd, status))
        if cmd == self.Cmd_Initiate_Pairing_Request_Api:
            # the command was closed by _evt_command_status: now we must tell
            # that the procedure was successfull
            self.gap_auth_resul_cb(0)
        else:
            self._close_command(cmd, status)

    def _evt_scan_progress_result(self, prm):
        _ = struct.unpack('<H', prm[:2])
        self.scan_progress_cb(prm[2:])

    def _evt_gatt_connect_ind(self, prm):
        cmd, conh = struct.unpack('<2H', prm)
        self._print(
            'EVT_ESTABLISH_CONNECTION_RESPONSE: cmd={:04X} handle={:04X}'.
            format(cmd, conh))
        self.connection['cyBle_connHandle'] = conh
        self.connection['mtu'] = 23

    def _evt_gap_enhance_conn_complete(self, prm):
        cmd, status, conh, role = struct.unpack('<HBHB', prm[:6])
        self._print(
            'EVT_ENHANCED_CONNECTION_COMPLETE: cmd={:04X} status={} handle={:04X} role='
            .format(cmd, status, conh) + 'master' if role == 0 else 'slave')

    def _evt_gap_auth_req(self, prm):
        """
        EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION [7]:
        04 00 	cyBle_connHandle
                CYBLE_GAP_AUTH_INFO_T
        02 		security
        00 		bonding
        07 		ekeySize
        00 		authErr
        00		pairingProperties
        """
        _, security, bonding, ekeySize, _, pairingProperties = struct.unpack(
            '<H5B', prm)
        ai = {
            'security': security,
            'bonding': bonding,
            'ekeySize': ekeySize,
            'pairingProperties': pairingProperties
        }
        self.gap_auth_req_cb(ai)

    def _evt_gap_data_length_change(self, prm):
        """
        EVT_DATA_LENGTH_CHANGED_NOTIFICATION [10]:
        04 00   cyBle_connHandle
                CYBLE_GAP_CONN_DATA_LENGTH_T
        1B 00   connMaxTxOctets
        48 01   connMaxTxTime
        1B 00   connMaxRxOctets
        48 01   connMaxRxTime
        """
        _, txo, txt, rxo, rxt = struct.unpack('<5H', prm)
        self._print('EVT_DATA_LENGTH_CHANGED_NOTIFICATION: ' +
                    'connMaxTxOctets={} '.format(txo) +
                    'connMaxTxTime={} '.format(txt) +
                    'connMaxRxOctets={} '.format(rxo) +
                    'connMaxRxTime={}'.format(rxt))

    def _evt_negotiated_pairing_parameters(self, prm):
        """
        EVT_NEGOTIATED_PAIRING_PARAMETERS [8]:
        04 00 cyBle_connHandle
        00    reason (AUTH_PARAM_NEGOTIATED=0=CYBLE_EVT_GAP_SMP_NEGOTIATED_AUTH_INFO
                      AUTH_COMPLETED=1=CYBLE_EVT_GAP_AUTH_COMPLETE
              CYBLE_GAP_AUTH_INFO_T
        02 	  security
        00 	  bonding
        07 	  ekeySize
        00 	  authErr
        00	  pairingProperties
        """
        _, reason, _, _, _, authErr, _ = struct.unpack('<H6B', prm)
        self._print(
            'EVT_NEGOTIATED_PAIRING_PARAMETERS: reason={} authErr={}'.format(
                reason, authErr))

    def _evt_gap_passkey_entry_request(self, _):
        """
        EVT_PASSKEY_ENTRY_REQUEST [4]:
            99 FE command
            04 00 cyBle_connHandle
        """
        self.gap_passkey_entry_request_cb()

    def _evt_gattc_xchng_mtu_rsp(self, prm):
        """
        EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE [6]:
            12 FE command
            04 00 cyBle_connHandle
            17 00 mtu
        """
        _, _, mtu = struct.unpack('<3H', prm)
        self.connection['mtu'] = mtu
        self._print('EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE: mtu={}'.format(mtu))

    def _evt_gap_auth_failed(self, prm):
        """
        EVT_AUTHENTICATION_ERROR_NOTIFICATION [5]:
            99 FE command
            04 00 cyBle_connHandle
            03    reason
        """
        _, _, reason = struct.unpack('<2HB', prm)
        self.gap_auth_resul_cb(reason)

    def _evt_gap_device_disconnected(self, prm):
        """
        EVT_CONNECTION_TERMINATED_NOTIFICATION [3]:
            04 00 cyBle_connHandle
            13    CYBLE_HCI_ERROR_T
        """
        _, reason = struct.unpack('<HB', prm)
        self.connection['cyBle_connHandle'] = None
        self.gap_device_disconnected_cb(reason)

    def _evt_report_stack_misc_status(self, prm):
        """
        EVT_REPORT_STACK_MISC_STATUS [5]:
            29 00 event
            01 00 prm size
            01    prm
        """
        event, dim = struct.unpack('<2H', prm[:4])
        prm = prm[4:]
        self._print('EVT_REPORT_STACK_MISC_STATUS: CYBLE_EVT_={:04X}[{}] '.
                    format(event, dim) + utili.esa_da_ba(prm, ' '))

    def _evt_gattc_handle_value_ntf(self, prm):
        # connHandle, attrHandle, len
        _, crt, _ = struct.unpack('<3H', prm[:6])
        ntf = prm[6:]
        self.gattc_handle_value_ntf_cb(crt, ntf)

    def _evt_gattc_handle_value_ind(self, prm):
        # connHandle, attrHandle, result of CyBle_GattcConfirmation, len
        _, crt, result, _ = struct.unpack('<4H', prm[:8])
        self.gattc_handle_value_ind_cb(crt, result, prm[8:])

    def _evt_get_bluetooth_device_address_response(self, prm):
        # command, bda, type
        cmd = struct.unpack('<H', prm[:2])
        self._save_data(cmd[0], prm[2:8])

    def _evt_scan_stopped_notification(self, _):
        self._print('EVT_SCAN_STOPPED_NOTIFICATION')

    def _evt_get_scan_parameters_response(self, prm):
        cmd = struct.unpack('<H', prm[:2])
        self._save_data(cmd[0], prm[2:])

    def _evt_get_tx_power_response(self, prm):
        cmd = struct.unpack('<H', prm[:2])
        self._save_data(cmd[0], prm[2:])

    def _evt_get_rssi_response(self, prm):
        cmd = struct.unpack('<H', prm[:2])
        self._save_data(cmd[0], prm[2:])

    def _evt_gatt_error_notification(self, prm):
        """
        EVT_GATT_ERROR_NOTIFICATION [8]:
        0B FE cmd
        04 00 connHandle
        12    GattErrResp->opCode
        15 00 GattErrResp->attrHandle
        0E    GattErrResp->errorCode
        """
        cmd, _, pdu, _, error = struct.unpack('<2HBHB', prm)
        self._print('EVT_GATT_ERROR_NOTIFICATION ' + cc.quale_pdu(pdu) + ' ' +
                    cc.quale_errore(error))
        if cmd in (self.Cmd_Discover_All_Primary_Services_Api,
                   self.Cmd_Discover_Primary_Services_By_Uuid_Api,
                   self.Cmd_Discover_All_Characteristics_Api):
            # always return CYBLE_GATT_ERR_ATTRIBUTE_NOT_FOUND
            self._close_command(cmd, 0)
        else:
            self._close_command(cmd, error)

    def _evt_gattc_read_rsp(self, prm):
        """
        EVT_READ_CHARACTERISTIC_VALUE_RESPONSE
        cmd, connHandle, len, dati
        """
        cmd, _, _ = struct.unpack('<3H', prm[:6])
        self._save_data(cmd, prm[6:])

    def _evt_gattc_find_by_type_value_rsp(self, prm):
        """
        CYBLE_EVT_GATTC_FIND_BY_TYPE_VALUE_RSP
        cmd, connHandle, startHandle, endHandle
        """
        cmd, _, sh, endh = struct.unpack('<4H', prm)
        # The sequence of operations is complete when ...
        # or when the End Group Handle in the Find By Type Value Response is
        # 0xFFFF
        if endh == 0xFFFF:
            self._close_command(cmd, 0)
        elif cmd == self.Cmd_Discover_Primary_Services_By_Uuid_Api:
            srv = {'starth': sh, 'endh': endh}
            self.services['current'].append(srv)

    def _evt_gattc_read_by_group_type_rsp(self, prm):
        """
        CYBLE_EVT_GATTC_READ_BY_GROUP_TYPE_RSP
        cmd connHandle [sh eh type uuid], ...
        """
        _, _ = struct.unpack('<2H', prm[:4])
        prm = prm[4:]
        while len(prm):
            sh, eh, stype = struct.unpack('<2HB', prm[:5])
            srv = {'starth': sh, 'endh': eh}
            prm = prm[5:]
            if stype == 1:
                uid16 = struct.unpack('<H', prm[:2])[0]
                srv['uuid16'] = uid16
                prm = prm[2:]
                #print('start={:04X} end={:04X} uuid={:04X}'.format(sh, eh, uid16))
            else:
                uid128 = prm[:16]
                srv['uuid128'] = stringuuid_from_ba(uid128)
                prm = prm[16:]
                #print('start={:04X} end={:04X} uuid='.format(sh, eh) + srv['uuid128'])
            self.services['primary'].append(srv)

    def _evt_gattc_read_by_type_rsp_chr_uid(self, prm):
        """
        CYBLE_EVT_GATTC_READ_BY_TYPE_RSP + CMD_DISCOVER_CHARACTERISTICS_BY_UUID
        cmd connHandle [attrh prop valh], ...
        """
        _, _ = struct.unpack('<2H', prm[:4])
        prm = prm[4:]
        while len(prm) >= 5:
            attr, prop, value = struct.unpack('<HBH', prm[:5])
            chrt = {
                'attr': attr,
                'prop': cc.char_properties(prop),
                'value': value
            }
            self.services['char'].append(chrt)
            prm = prm[5:]

    def _evt_gattc_read_by_type_rsp_all_char(self, prm):
        """
        CYBLE_EVT_GATTC_READ_BY_TYPE_RSP + CMD_DISCOVER_ALL_CHARACTERISTICS
        cmd connHandle [attrh prop valh uidtype uid], ...
        """
        _, _ = struct.unpack('<2H', prm[:4])
        prm = prm[4:]
        while len(prm) >= 2 + 1 + 2 + 1 + 2:
            attr, prop, value, uidtype = struct.unpack('<HBHB', prm[:6])
            prm = prm[6:]
            chrt = {
                'attr': attr,
                'prop': cc.char_properties(prop),
                'value': value
            }
            if uidtype == 1:
                chrt['uuid16'] = struct.unpack('<H', prm[:2])[0]
                prm = prm[2:]
            else:
                chrt['uuid128'] = stringuuid_from_ba(prm[:16])
                prm = prm[16:]
            self.services['char'].append(chrt)

    def _evt_gattc_find_info_rsp(self, prm):
        """
        CYBLE_EVT_GATTC_FIND_INFO_RSP
        cmd connHandle [attrh uidtype uid], ...
        """
        _, _ = struct.unpack('<2H', prm[:4])
        prm = prm[4:]
        while len(prm) >= 2 + 1 + 2:
            attr, uidtype = struct.unpack('<HB', prm[:3])
            prm = prm[3:]
            chrt = {
                'attr': attr,
            }
            if uidtype == 1:
                chrt['uuid16'] = struct.unpack('<H', prm[:2])[0]
                prm = prm[2:]
            else:
                chrt['uuid128'] = stringuuid_from_ba(prm[:16])
                prm = prm[16:]
            self.services['char'].append(chrt)

    def _send_command_and_wait(self, cod, prm=None, to=5):
        # send
        cmd = _COMMAND(cod, prm)
        self.command['todo'].put_nowait(cmd)

        # wait
        res = cmd.get_result(to)
        if res is None:
            # abort
            self.command['todo'].put_nowait(
                _COMMAND(self.ABORT_CURRENT_COMMAND))
            return False

        return res

    def _exec_command(self):
        try:
            cmd = self.command['todo'].get(True, self.command['poll'])

            if cmd.are_you(self.QUIT):
                return False

            if cmd.are_you(self.ABORT_CURRENT_COMMAND):
                self.command['curr'] = None
                raise utili.Problema('abort')

            if self.command['curr'] is None:
                self.command['curr'] = cmd

                msg = self.proto['tx'].compose(cmd.get())

                self._print('IRP_MJ_WRITE Data: ' + utili.esa_da_ba(msg, ' '))
                self.uart.write(msg)
            else:
                # busy
                self.command['todo'].put_nowait(cmd)
        except (utili.Problema, queue.Empty) as err:
            if isinstance(err, utili.Problema):
                self._print(str(err))

        return True

    def run(self):
        self._print('nasco')
        while True:
            # any command?
            if not self._exec_command():
                # quit
                break

            # any data?
            while self.uart.in_waiting:
                tmp = self.uart.read(self.uart.in_waiting)
                if len(tmp) == 0:
                    break

                self._print('IRP_MJ_READ Data: ' + utili.esa_da_ba(tmp, ' '))
                self.proto['rx'].examine(tmp)

            # any message?
            while True:
                msg = self.proto['rx'].get_msg()
                if msg is None:
                    break

                dec = self.proto['rx'].decompose(msg)
                if any(dec):
                    try:
                        self.events[dec['evn']](dec['prm'])
                    except KeyError:
                        self._print('PLEASE MANAGE ' +
                                    self.proto['rx'].msg_to_string(msg))
        self._print('muoio')

        # switch dongle to initial configuration
        cmd = _COMMAND(self.Cmd_Tool_Disconnected_Api)
        msg = self.proto['tx'].compose(cmd.get())

        self._print('IRP_MJ_WRITE Data: ' + utili.esa_da_ba(msg, ' '))
        self.uart.write(msg)

    def close(self):
        """
        kill the thd and close the serial port
        :return: n.a.
        """
        if self.uart is not None:
            # kill the thd
            ktt = _COMMAND(self.QUIT)

            self.command['todo'].put_nowait(ktt)

            # wait
            self.join()

            # close the serial port
            self.uart.close()
            self.uart = None

    def is_ok(self):
        """
        ok means that the serial port was opened
        :return: bool
        """
        return self.uart is not None

    def init_ble_stack(self):
        """
        send the command that stops and then restart bluetooth
        :return: bool
        """
        self._print('init_ble_stack')
        return self._send_command_and_wait(self.Cmd_Init_Ble_Stack_Api)

    def get_rssi(self):
        self._print('get_rssi')
        rsp = self._send_command_and_wait(self.Cmd_Get_Rssi_Api)
        if not isinstance(rsp, bool):
            return struct.unpack('<b', rsp)[0]

        return None

    def get_txpowerlevel(self, conn=True):
        """
        get the power level of the channel
        :param conn: channel (True == connection, False == advertising)
        :return: dict or None
        """
        self._print('get_txpowerlevel')
        prm = bytearray([1 if conn else 0])
        rsp = self._send_command_and_wait(
            self.Cmd_Get_TxPowerLevel_Api, prm=prm)
        if not isinstance(rsp, bool):
            chg, pl = struct.unpack('<BB', rsp)
            return {
                'channel': 'CONN' if chg == 1 else 'ADV',
                'power': desc_tp(pl)
            }

        return None

    def set_txpowerlevel(self, conn=True, pot=3):
        self._print('set_txpowerlevel')

        prm = struct.pack('<BB',
                          1 if conn else 0,
                          val_tp(pot))

        return self._send_command_and_wait(
            self.Cmd_Set_TxPowerLevel_Api, prm=prm)

    def my_address(self, public=True):
        """
        get the dongle address
        :param public: kind of address (public/random)
        :return: bytearray or None
        """
        self._print('my_address')
        prm = bytearray([0 if public else 1])
        rsp = self._send_command_and_wait(
            self.Cmd_Get_Bluetooth_Device_Address_Api, prm=prm)
        if not isinstance(rsp, bool):
            return rsp

        return None

    def get_scan_parameters(self):
        """
        get the parameters currently used

        :return: dict or None
        """
        self._print('get_scan_parameters')
        rsp = self._send_command_and_wait(
            self.Cmd_Get_Scan_Parameters_Api)
        if not isinstance(rsp, bool):
            discProcedure, tipo, intv, window, ownAddrType, filterPolicy, to, filterDuplicates = struct.unpack(
                '<BBHHBBHB', rsp)

            return {
                'discProcedure': desc_dp(discProcedure),
                'active': tipo == 1,
                'interval': intv * 0.625,
                'window': window * 0.625,
                'ownAddrType': desc_at(ownAddrType),
                'filterPolicy': desc_fp(filterPolicy),
                'to': to,
                'filterDuplicates': filterDuplicates == 1,
            }

        return None

    def set_scan_parameters(self, sp):
        self._print('set_scan_parameters')

        prm = struct.pack('<BBHHBBHB',
                          valore(sp['discProcedure'], DISCOVERY_PROC),
                          1 if sp['active'] else 0,
                          int(sp['interval'] / 0.625),
                          int(sp['window'] / 0.625),
                          valore(sp['ownAddrType'], ADDRESS_TYPE),
                          valore(sp['filterPolicy'], FILTER_POLICY),
                          sp['to'],
                          1 if sp['filterDuplicates'] else 0)

        return self._send_command_and_wait(
            self.Cmd_Set_Scan_Parameters_Api, prm=prm)

    def scan_start(self):
        """
        start scanning for devices
        :return: bool
        """
        self._print('scan_start')
        return self._send_command_and_wait(self.Cmd_Start_Scan_Api)

    def scan_stop(self):
        """
        stop scanning
        :return: bool
        """
        self._print('scan_stop')
        return self._send_command_and_wait(self.Cmd_Stop_Scan_Api)

    def set_local_device_security(self, level):
        """
        configure cyBle_authInfo
        :param level: '1': No Security (No Authentication & No Encryption)
                      '2': Unauthenticated pairing with encryption
                      '3': Authenticated pairing with encryption
        :return: bool
        """
        self._print('set_local_device_security')
        if level in ('1', '2', '3'):
            # Mode 1
            security = 0x10 + int(level) - 1
            # No bonding
            bonding = 0
            # 16 bit keys
            ekeySize = 16
            # this is an output
            authErr = 0
            # no prop
            pairingProperties = 0
            # don't force secure connections (this should be done by the perip)
            CyBle_GapSetSecureConnectionsOnlyMode = 0

            prm = struct.pack('<6B', security, bonding, ekeySize, authErr,
                              pairingProperties,
                              CyBle_GapSetSecureConnectionsOnlyMode)

            return self._send_command_and_wait(
                self.Cmd_Set_Local_Device_Security_Api, prm=prm)

        return False

    def set_device_io_capabilities(self, capa):
        """
        can influence secutity
        :param capa: cfr CAPA
        :return: bool
        """
        self._print('set_device_io_capabilities')
        try:
            prm = bytearray([IO_CAPABILITIES[capa]])
            return self._send_command_and_wait(
                self.Cmd_Set_Device_Io_Capabilities_Api, prm=prm)
        except KeyError:
            return False

    def connect(self, bda, public=True):
        """
        connect to the device
        :param bda: string
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is None:
            self._print('connect')
            prm = utili.mac_da_str(bda)
            prm.append(0 if public else 1)

            return self._send_command_and_wait(
                self.Cmd_Establish_Connection_Api, prm=prm, to=10)

        # only one device at a time
        return False

    def disconnect(self):
        """
        close the connection to the device
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('disconnect')
            prm = struct.pack('<H', self.connection['cyBle_connHandle'])
            return self._send_command_and_wait(
                self.Cmd_Terminate_Connection_Api, prm=prm)

        # no connections: so I have executed the disconnection!
        return True

    def find_primary_service(self, suid, to=10):
        """
        check if the service uuid is present
        :param suid: string
        :param to: timeout
        :return: dict or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('find_primary_service')

            self.services['current'] = []

            prm = struct.pack('<HB', self.connection['cyBle_connHandle'], 2)
            prm += ba_from_stringuuid(suid)
            if self._send_command_and_wait(
                    self.Cmd_Discover_Primary_Services_By_Uuid_Api, prm=prm,
                    to=to):
                if any(self.services['current']):
                    return self.services['current'][0]

        # no connection, no service
        return None

    def find_primary_services(self, to=10):
        """
        find all the services
        :param to: timeout
        :return: list of dict or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('find_primary_services')

            self.services['primary'] = []

            prm = struct.pack('<H', self.connection['cyBle_connHandle'])
            if self._send_command_and_wait(
                    self.Cmd_Discover_All_Primary_Services_Api, prm=prm,
                    to=to):
                if any(self.services['primary']):
                    return self.services['primary']

        # no connection, no service
        return None

    def discover_characteristics_by_uuid(self, sehu, to=10):
        """
        find all the characteristics
        :param sehu: dict (e.g. from find_primary_services)
        :param to: timeout
        :return: list of dict or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('discover_characteristics_by_uuid')

            self.services['char'] = []

            prm = struct.pack('<HB', self.connection['cyBle_connHandle'], 2)
            prm += ba_from_stringuuid(sehu['uuid128'])
            prm += struct.pack('<2H', sehu['starth'], sehu['endh'])
            if self._send_command_and_wait(
                    self.Cmd_Discover_Characteristics_By_Uuid_Api, prm=prm,
                    to=to):
                if any(self.services['char']):
                    return self.services['char']

        # no connection, no characteristics
        return None

    def discover_all_characteristics(self, sehu, to=10):
        """
        find all characteristic declarations within a service definition
        :param sehu: dict (e.g. from find_primary_services)
        :param to: timeout
        :return: list of dict or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('discover_all_characteristics')

            self.services['char'] = []

            prm = struct.pack('<H', self.connection['cyBle_connHandle'])
            prm += struct.pack('<2H', sehu['starth'], sehu['endh'])
            if self._send_command_and_wait(
                    self.Cmd_Discover_All_Characteristics_Api, prm=prm, to=to):
                if any(self.services['char']):
                    return self.services['char']

        return None

    def discover_characteristic_descriptors(self, charh, to=10):
        """
        find all the characteristic descriptors
        :param charh: handle of the characteristic
        :param to: timeout
        :return: list of dict
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('discover_all_characteristic_descriptors')

            self.services['char'] = []

            prm = struct.pack('<3H', self.connection['cyBle_connHandle'],
                              charh, charh)
            if self._send_command_and_wait(
                    self.Cmd_Discover_All_Characteristic_Descriptors_Api,
                    prm=prm,
                    to=to):
                if any(self.services['char']):
                    return self.services['char']

        return None

    def exchange_gatt_mtu_size(self, mtu=512):
        """
        try to change mtu size
        :param mtu: 23 <= mtu <= 512
        :return: mtu or 0 if error
        """
        if not 23 <= mtu <= 512:
            return 0

        if self.connection['cyBle_connHandle'] is not None:
            self._print('exchange_gatt_mtu_size')
            prm = struct.pack('<2H', self.connection['cyBle_connHandle'], mtu)
            if self._send_command_and_wait(self.Cmd_Exchange_GATT_MTU_Size_Api,
                                           prm=prm):
                return self.connection['mtu']

        return 0

    def _write(self, crt, dati, cmd, to=5):
        """
        writes with the common limit of mtu - 3

        CYBLE_EVT_GATTC_WRITE_RSP -> comm complete
        CYBLE_EVT_GATTC_ERROR_RSP -> EVT_GATT_ERROR_NOTIFICATION
        """
        mtu = self.connection['mtu']
        if len(dati) > mtu - 3:
            dati = dati[:mtu - 3]

        prm = struct.pack('<3H', self.connection['cyBle_connHandle'], crt,
                          len(dati))
        prm += dati
        return self._send_command_and_wait(cmd, prm=prm, to=to)

    def write_without_response(self, crt, dati):
        """
        bt 4.2 - vol 3 - part G - 4.9.1

        :param crt: handle
        :param dati: bytearray
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('write_without_response')

            return self._write(
                crt, dati,
                self.Cmd_Characteristic_Value_Write_Without_Response_Api)

        return False

    def write_characteristic_value(self, crt, dati, to=5):
        """
        bt 4.2 - vol 3 - part G - 4.9.3

        :param crt: handle
        :param dati: bytearray
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('write_characteristic_value')

            return self._write(crt, dati,
                               self.Cmd_Write_Characteristic_Value_Api, to)

        return False

    def write_characteristic_descriptor(self, crt, ntf=False, ndc=False, to=5):
        """
        enable/disable notifications and/or indications
        :param crt: handle
        :param ntf: True to enable notifications
        :param ndc: True to enable indications
        :param to: timeout
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('write_characteristic_descriptor')
            dati = 0
            if ntf:
                dati += 1
            if ndc:
                dati += 2

            return self._write(crt, bytearray([dati]),
                               self.Cmd_Write_Characteristic_Descriptor_Api,
                               to)

        return False

    def write_long_characteristic_value(self, crt, dati, ofs=0, to=10):
        """
        bt 4.2 - vol 3 - part G - 4.9.4

        :param crt: handle
        :param dati: bytearray
        :param ofs: starting position
        :param: to: timeout
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('write_long_characteristic_value')

            prm = struct.pack('<4H', self.connection['cyBle_connHandle'], crt,
                              ofs, len(dati))
            prm += dati
            return self._send_command_and_wait(
                self.Cmd_Write_Long_Characteristic_Value_Api, prm=prm, to=to)

        return False

    def write_char_best(self, crt, dati, to=10):
        """
        write a characteristic with simple write or write long

        :param crt: handle
        :param dati: bytearray
        :param to:  timeout
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            mtu = self.connection['mtu']
            if len(dati) > mtu - 3:
                return self.write_long_characteristic_value(crt, dati, to=to)

            return self.write_characteristic_value(crt, dati, to=to)

        return False

    def read_characteristic_value(self, crt, to=10):
        """
        bt 4.2 - vol 3 - part G - 4.8.1

        max mtu - 1 byte

        :param crt: handle
        :param to: timeout
        :return: bytearray or None

        CYBLE_EVT_GATTC_READ_RSP
        CYBLE_EVT_GATTC_ERROR_RSP
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('read_characteristic_value')

            prm = struct.pack('<2H', self.connection['cyBle_connHandle'], crt)

            res = self._send_command_and_wait(
                self.Cmd_Read_Characteristic_Value_Api, prm=prm, to=to)
            if not isinstance(res, bool):
                return res

        return None

    def read_long_characteristic_value(self, crt, ofs=0, to=10):
        """
        bt 4.2 - vol 3 - part G - 4.8.3

        :param crt: handle
        :param ofs: starting position
        :param to: timeout
        :return: bytearray or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('read_long_characteristic_value')

            prm = struct.pack('<3H', self.connection['cyBle_connHandle'], crt,
                              ofs)

            res = self._send_command_and_wait(
                self.Cmd_Read_Long_Characteristic_Values_Api, prm=prm, to=to)
            if not isinstance(res, bool):
                return res

        return None

    def read_char_best(self, crt, dim, to=10):
        """
        uses read or read long depending on the expected dimension

        :param crt: handle
        :param dim: expected
        :param to: timeout
        :return: bytearray or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            mtu = self.connection['mtu']
            if dim <= mtu - 1:
                return self.read_characteristic_value(crt, to=to)

            return self.read_long_characteristic_value(crt, to=to)

        return None

    def read_characteristic_descriptor(self, crt, to=5):
        """
        read notifications and indications state
        :param crt: handle
        :param to: timeout
        :return: tuple (notif, indic) or None
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('read_characteristic_descriptor')

            prm = struct.pack('<2H', self.connection['cyBle_connHandle'], crt)

            res = self._send_command_and_wait(
                self.Cmd_Read_Characteristic_Descriptor_Api, prm=prm, to=to)
            if not isinstance(res, bool):
                val = struct.unpack('<H', res)[0]
                ntf = False
                ndc = False
                if val & 1:
                    ntf = True
                if val & 2:
                    ndc = True
                return ntf, ndc

        return None

    def initiate_pairing_request(self):
        """
        Invoke after gap_auth_req_cb
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('initiate_pairing_request')
            prm = struct.pack('<H', self.connection['cyBle_connHandle'])
            return self._send_command_and_wait(
                self.Cmd_Initiate_Pairing_Request_Api, prm=prm)

        return False

    def pairing_passkey(self, pk):
        """
        Invoke after gap_passkey_entry_request_cb
        :param pk: 0 <= passkey <= 999999
        :return: bool
        """
        if self.connection['cyBle_connHandle'] is not None:
            self._print('pairing_passkey')
            prm = struct.pack('<HIB', self.connection['cyBle_connHandle'], pk,
                              1)
            return self._send_command_and_wait(self.Cmd_Pairing_PassKey_Api,
                                               prm=prm)

        return False

    # pylint: disable=no-self-use
    def scan_progress_cb(self, adv):
        """
        callback invoked when an advertisement is received
        :param adv: bytearray
        :return: n.a.
        """
        sr = scan_report(adv)
        adv = scan_advertise(sr['data'])
        print(str(adv))

    def gap_auth_req_cb(self, ai):
        """
        callback invoked when an authentication request is received
        :param ai: dictionary with (cfr CYBLE_GAP_AUTH_INFO_T):
                   'security', 'bonding', 'ekeySize', 'pairingProperties'
        :return: n.a.
        """
        self._print(str(ai))

    def gap_passkey_entry_request_cb(self):
        """
        callback invoked when the passkey request is received
        :return: n.a.
        """
        self._print('gap_passkey_entry_request_cb')

    def gap_auth_resul_cb(self, reason):
        """
        callback invoked when the authentication procedure terminates
        :param reason: byte (0=success, != cfr CYBLE_GAP_AUTH_FAILED_REASON_T)
        :return: n.a.
        """
        self._print('gap_auth_resul_cb: {}'.format(reason))

    def gap_device_disconnected_cb(self, reason):
        """
        callback invoked when the peripheral disconnets
        :param reason: CYBLE_HCI_ERROR_T
        :return: n.a.
        """
        self._print('gap_device_disconnected_cb: {}'.format(reason))

    def gattc_handle_value_ntf_cb(self, crt, ntf):
        """
        callback invoked when the peripheral sends a notification
        :param crt: characteristic's handle
        :param ntf: notification (bytearray)
        :return: n.a.
        """
        self._print('gattc_handle_value_ntf_cb: handle:{:04X} '.format(crt) +
                    utili.esa_da_ba(ntf, ' '))

    def gattc_handle_value_ind_cb(self, crt, result, ind):
        """
        callback invoked when the peripheral sends an indication
        :param crt: characteristic's handle
        :param result: of CyBle_GattcConfirmation
        :param ind: bytearray
        :return: n.a.
        """
        self._print('gattc_handle_value_ind_cb: handle:{:04X} confirm={}'.
                    format(crt, result) + utili.esa_da_ba(ind, ' '))


if __name__ == '__main__':
    import time

    DONGLE = CY567x()
    if not DONGLE.is_ok():
        print('uart error')
    else:
        print('init: ' + str(DONGLE.init_ble_stack()))

        ma = DONGLE.my_address()
        if ma is not None:
            print('I am ' + utili.str_da_mac(ma))
        else:
            print('I am ???')

        # scan
        print('start: ' + str(DONGLE.scan_start()))

        time.sleep(5)

        print('stop: ' + str(DONGLE.scan_stop()))

        # connect
        # print('secu: ' + str(DONGLE.set_local_device_security('1')))
        #
        # print('capa: ' + str(
        #     DONGLE.set_device_io_capabilities('KEYBOARD DISPLAY')))
        #
        # print('conn: ' + str(DONGLE.connect('00:A0:50:C4:A4:2D')))

        time.sleep(2)

        DONGLE.close()

        DONGLE = None
