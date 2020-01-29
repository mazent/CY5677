"""
manages two cypress dongles: CY5677 and CY5670 (old)
"""
import threading
import queue
import struct
import datetime

import serial

import utili
import cyproto as prt
import cycost as cc

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

ADVERTISEMENT_EVENT_TYPE = {
    0x00: 'Connectable undirected advertising',
    0x01: 'Connectable directed advertising',
    0x02: 'Scannable undirected advertising',
    0x03: 'Non connectable undirected advertising',
    0x04: 'Scan Response'
}

ADDRESS_TYPE = {
    0x00: 'Public Device Address',
    0x01: 'Random Device Address',
    0x02: 'Public Resolvable Address',
    0x03: 'Random Resolvable Address'
}


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

    def save(self, this):
        self._depot = this


def scan_report(adv):
    """
    utility to decompose an advertise (cfr Send_advt_report)
    :param adv: bytearray
    :return: scan report
    """
    sr = {
        'adv_type': ADVERTISEMENT_EVENT_TYPE[adv[0]],
        'bda': utili.str_da_mac(adv[1:7])
    }

    bda_type, rssi, dim = struct.unpack('<BbB', adv[7:10])
    sr['bda_type'] = ADDRESS_TYPE[bda_type]
    sr['rssi'] = rssi
    sr['data'] = adv[10:]
    if len(sr['data']) != dim:
        sr['err'] = 'dim'

    return sr


class CY567x(threading.Thread):
    """
    manages two cypress dongles: CY5677 and CY5670 (old)
    """
    # internal commands
    QUIT = 0xE5C1
    ABORT_CURRENT_COMMAND = 0xACC0
    # dongle commands (cfr CySmt_CommandLayer.c)
    Cmd_Init_Ble_Stack_Api = 0xFC07
    Cmd_Get_Bluetooth_Device_Address_Api = 0xFE82
    Cmd_Start_Scan_Api = 0xFE93
    Cmd_Stop_Scan_Api = 0xFE94
    Cmd_Set_Local_Device_Security_Api = 0xFE8D
    Cmd_Set_Device_Io_Capabilities_Api = 0xFE80
    Cmd_Establish_Connection_Api = 0xFE97
    Cmd_Exchange_GATT_MTU_Size_Api = 0xFE12
    Cmd_Initiate_Pairing_Request_Api = 0xFE99
    Cmd_Pairing_PassKey_Api = 0xFE9B
    Cmd_Terminate_Connection_Api = 0xFE98

    def __init__(self, BAUD=BAUD_CY5677, poll=0.1, porta=None):
        self.proto = {
            'rx': prt.PROTO_RX(),
            'tx': prt.PROTO_TX()
        }

        self.events = {
            cc.EVT_COMMAND_STATUS: self._evt_command_status,
            cc.EVT_COMMAND_COMPLETE: self._evt_command_complete,
            cc.EVT_SCAN_PROGRESS_RESULT: self._evt_scan_progress_result,
            cc.EVT_ESTABLISH_CONNECTION_RESPONSE: self._evt_gatt_connect_ind,
            cc.EVT_ENHANCED_CONNECTION_COMPLETE: self._evt_gap_enhance_conn_complete,
            cc.EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION: self._evt_gap_auth_req,
            cc.EVT_DATA_LENGTH_CHANGED_NOTIFICATION: self._evt_gap_data_length_change,
            cc.EVT_NEGOTIATED_PAIRING_PARAMETERS: self._evt_negotiated_pairing_parameters,
            cc.EVT_PASSKEY_ENTRY_REQUEST: self._evt_gap_passkey_entry_request,
            cc.EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE: self._evt_gattc_xchng_mtu_rsp,
            cc.EVT_AUTHENTICATION_ERROR_NOTIFICATION: self._evt_gap_auth_failed,
            cc.EVT_CONNECTION_TERMINATED_NOTIFICATION: self._evt_gap_device_disconnected,
            cc.EVT_REPORT_STACK_MISC_STATUS: self._evt_report_stack_misc_status,
            cc.EVT_CHARACTERISTIC_VALUE_NOTIFICATION: self._evt_gattc_handle_value_ntf,
            cc.EVT_CHARACTERISTIC_VALUE_INDICATION: self._evt_gattc_handle_value_ind,
            cc.EVT_GET_BLUETOOTH_DEVICE_ADDRESS_RESPONSE: self._evt_get_bluetooth_device_address_response
        }

        self.connection = {
            'mtu': 23,
            'cyBle_connHandle': None
        }

        self.command = {
            'curr': None,
            'todo': queue.Queue(),
            'poll': poll,
        }

        try:
            serial_open = serial.Serial
            if porta is None:
                porta = 'hwgrep://04B4:F139'
                serial_open = serial.serial_for_url

            self.uart = serial_open(
                porta,
                baudrate=BAUD,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1,
                rtscts=True)

            # posso girare
            threading.Thread.__init__(self)
            self.start()

        except serial.SerialException as err:
            self._print(str(err))
            self.uart = None

    def __del__(self):
        self._print('del')
        self.close()

    def _print(self, msg):
        adesso = datetime.datetime.now()
        sadesso = '{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03.0f}: '.format(
            adesso.year, adesso.month, adesso.day, adesso.hour, adesso.minute,
            adesso.second, adesso.microsecond / 1000.0)

        print(sadesso + msg)

    def _close_command(self, cod, resul):
        if self.command['curr'] is None:
            self._print('no cmd waiting')
        elif self.command['curr'].are_you(cod):
            self.command['curr'].set_result(resul == 0)
            self.command['curr'] = None
        else:
            self._print('wrong cmd')

    def _evt_command_status(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        self._print(
            'EVT_COMMAND_STATUS: cmd={:04X} stt={}'.format(
                cmd, status))
        if cmd in (self.Cmd_Start_Scan_Api,
                   self.Cmd_Initiate_Pairing_Request_Api):
            self._close_command(cmd, status)

    def _evt_command_complete(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        self._print(
            'EVT_COMMAND_COMPLETE: cmd={:04X} stt={}'.format(
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
            'EVT_ESTABLISH_CONNECTION_RESPONSE: cmd={:04X} handle={:04X}'.format(
                cmd, conh))
        self.connection['cyBle_connHandle'] = conh
        self.connection['mtu'] = 23

    def _evt_gap_enhance_conn_complete(self, prm):
        cmd, status, conh, role = struct.unpack('<HBHB', prm[:6])
        self._print(
            'EVT_ENHANCED_CONNECTION_COMPLETE: cmd={:04X} status={} handle={:04X} role='.format(
                cmd, status, conh) + 'master' if role == 0 else 'slave')

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
        self._print(
            'EVT_DATA_LENGTH_CHANGED_NOTIFICATION: connMaxTxOctets={} connMaxTxTime={} connMaxRxOctets={} connMaxRxTime={}'.format(
                txo,
                txt,
                rxo,
                rxt))

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
        _, reason, _, _, _, authErr, _ = struct.unpack(
            '<H6B', prm)
        self._print(
            'EVT_NEGOTIATED_PAIRING_PARAMETERS: reason={} authErr={}'.format(
                reason,
                authErr))

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
        self._print(
            'EVT_REPORT_STACK_MISC_STATUS: CYBLE_EVT_={:04X}[{}] '.format(
                event, dim) + utili.esa_da_ba(prm, ' '))

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
        self.command['curr'].save(prm[2:8])


    def _send_command_and_wait(self, cod, prm=None):
        # send
        cmd = _COMMAND(cod, prm)
        self.command['todo'].put_nowait(cmd)

        # wait
        res = cmd.get_result()
        if res is None:
            # abort
            self.command['todo'].put_nowait(
                _COMMAND(self.ABORT_CURRENT_COMMAND))
            return False

        return res

    def _send_command_and_wait_data(self, cod, prm=None):
        # send
        cmd = _COMMAND(cod, prm)
        self.command['todo'].put_nowait(cmd)

        # wait
        res = cmd.get_result()
        if res is None:
            # abort
            self.command['todo'].put_nowait(
                _COMMAND(self.ABORT_CURRENT_COMMAND))

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

                #msg = self.proto['tx'].compose(cmd.cod, cmd.prm)
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
                        self._print(
                            'PLEASE MANAGE ' +
                            self.proto['rx'].msg_to_string(msg))
        self._print('muoio')

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

    def my_address(self, public=True):
        """
        get the dongle address
        :param public: kind of address (public/random)
        :return: bytearray or None
        """
        prm = bytearray([0 if public else 1])
        return self._send_command_and_wait_data(self.Cmd_Get_Bluetooth_Device_Address_Api, prm=prm)


    def scan_start(self):
        """
        start scanning for devices
        :param cb: callback that will receive the advertise
                   You can call scan_report to decompose it
        :return: bool
        """
        return self._send_command_and_wait(self.Cmd_Start_Scan_Api)

    def scan_stop(self):
        """
        stop scanning
        :return: bool
        """
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

            prm = struct.pack(
                '<6B',
                security,
                bonding,
                ekeySize,
                authErr,
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
                self.Cmd_Establish_Connection_Api, prm=prm)

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

    def exchange_gatt_mtu_size(self, mtu):
        """
        try to change mtu size
        :param mtu: 23 <= mtu <= 512
        :return: mtu or 0 if error
        """
        if not 23 <= mtu <= 512:
            return 0

        if self.connection['cyBle_connHandle'] is not None:
            self._print('exchange_gatt_mtu_size')
            prm = struct.pack(
                '<2H', self.connection['cyBle_connHandle'], mtu)
            if self._send_command_and_wait(
                    self.Cmd_Exchange_GATT_MTU_Size_Api, prm=prm):
                return self.connection['mtu']

        return 0

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
            prm = struct.pack('<HIB', self.connection['cyBle_connHandle'],
                              pk, 1)
            return self._send_command_and_wait(
                self.Cmd_Pairing_PassKey_Api, prm=prm)

        return False

    def scan_progress_cb(self, adv):
        """
        callback invoked when an advertisement is received
        :param adv: bytearray
        :return: n.a.
        """
        sr = scan_report(adv)
        self._print(str(sr))

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
        self._print(
            'gattc_handle_value_ntf_cb: handle:{:04X} '.format(crt) +
            utili.esa_da_ba(ntf, ' '))

    def gattc_handle_value_ind_cb(self, crt, result, ind):
        """
        callback invoked when the peripheral sends an indication
        :param crt: characteristic's handle
        :param result: of CyBle_GattcConfirmation
        :param ind: bytearray
        :return: n.a.
        """
        self._print(
            'gattc_handle_value_ind_cb: handle:{:04X} confirm={}'.format(
                crt, result) +
            utili.esa_da_ba(ind, ' '))


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
