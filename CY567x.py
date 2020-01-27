"""
manages two cypress dongles: CY5677 and CY5670 (old)
"""
import threading
import queue
import struct

import serial

import utili
import cyproto as prt
import cycost as cc

BAUD_CY5670 = 115200
BAUD_CY5677 = 921600

CAPA = {
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


class _COMMAND:

    def __init__(self, cmd, prm=None, cb=None):
        self.cod = cmd
        self.prm = prm
        self.resul = queue.Queue()
        self.cb = cb

    def result(self, to=5):
        """
        wait for and return the result
        :param to: timeout in seconds
        :return: the result or None if to expires
        """
        try:
            return self.resul.get(True, to)
        except queue.Empty:
            return None

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
    # dongle commands
    Cmd_Init_Ble_Stack_Api = 0xFC07
    Cmd_Start_Scan_Api = 0xFE93
    Cmd_Stop_Scan_Api = 0xFE94
    Cmd_Set_Local_Device_Security_Api = 0xFE8D
    Cmd_Set_Device_Io_Capabilities_Api = 0xFE80

    def __init__(self, BAUD=BAUD_CY5677, poll=0.1, porta=None):
        self.proto = {
            'rx': prt.PROTO_RX(),
            'tx': prt.PROTO_TX()
        }

        self.events = {
            cc.EVT_COMMAND_STATUS: self._evt_command_status,
            cc.EVT_COMMAND_COMPLETE: self._evt_command_complete,
            cc.EVT_SCAN_PROGRESS_RESULT: self._evt_scan_progress_result
        }

        self.connection = {
            'mtu': 23,
            'cyBle_connHandle': None
        }

        self.command = {
            'curr': None,
            'todo': queue.Queue(),
            'poll': poll,
            'cb': None
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
            print(err)
            self.uart = None

    def __del__(self):
        print('del')
        self.close()

    def _close_command(self, cod, resul):
        if self.command['curr'] is None:
            print('no cmd waiting')
        elif self.command['curr'].cod == cod:
            self.command['curr'].resul.put_nowait(resul == 0)
            self.command['curr'] = None
        else:
            print('wrong cmd')

    def _evt_command_status(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        print('EVT_COMMAND_STATUS: cmd={:04X} stt={}'.format(cmd, status))
        if cmd == self.Cmd_Start_Scan_Api:
            self._close_command(cmd, status)

    def _evt_command_complete(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        print('EVT_COMMAND_COMPLETE: cmd={:04X} stt={}'.format(cmd, status))
        self._close_command(cmd, status)

    def _evt_scan_progress_result(self, prm):
        if self.command['cb'] is not None:
            _ = struct.unpack('<H', prm[:2])
            adv = prm[2:]
            self.command['cb'](adv)

    def _send_command_and_wait(self, cod, prm=None, cb=None):
        # send
        cmd = _COMMAND(cod, prm, cb)
        self.command['todo'].put_nowait(cmd)

        # wait
        res = cmd.result()
        if res is None:
            # abort
            self.command['todo'].put_nowait(
                _COMMAND(self.ABORT_CURRENT_COMMAND))
            return False

        return res

    def _exec_command(self):
        try:
            cmd = self.command['todo'].get(True, self.command['poll'])

            if cmd.cod == self.QUIT:
                return False

            if cmd.cod == self.ABORT_CURRENT_COMMAND:
                self.command['curr'] = None
                raise utili.Problema('abort')

            if self.command['curr'] is None:
                self.command['curr'] = cmd

                self.command['cb'] = cmd.cb

                msg = self.proto['tx'].compose(cmd.cod, cmd.prm)

                print('IRP_MJ_WRITE Data: ' + utili.esa_da_ba(msg, ' '))
                self.uart.write(msg)
            else:
                # busy
                self.command['todo'].put_nowait(cmd)
        except (utili.Problema, queue.Empty) as err:
            if isinstance(err, utili.Problema):
                print(err)

        return True

    def run(self):
        print('nasco')
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

                print('IRP_MJ_READ Data: ' + utili.esa_da_ba(tmp, ' '))
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
                        print(self.proto['rx'].msg_to_string(dec['prm']))
        print('muoio')

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
        return self._send_command_and_wait(self.Cmd_Init_Ble_Stack_Api)

    def scan_start(self, cb):
        """
        start scanning for devices
        :param cb: callback that will receive the advertise
                   You can call scan_report to decompose it
        :return: bool
        """
        return self._send_command_and_wait(self.Cmd_Start_Scan_Api, cb=cb)

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
        guess what
        :param capa: cfr CAPA
        :return: bool
        """
        try:
            prm = bytearray([CAPA[capa]])
            return self._send_command_and_wait(
                self.Cmd_Set_Device_Io_Capabilities_Api, prm=prm)
        except KeyError:
            return False


if __name__ == '__main__':
    import time

    def scan_rep(adv):
        sr = scan_report(adv)
        print(sr)

    DONGLE = CY567x()
    if not DONGLE.is_ok():
        print('uart error')
    else:
        print('init: ' + str(DONGLE.init_ble_stack()))

        print('secu: ' + str(DONGLE.set_local_device_security('1')))

        print('capa: ' + str(DONGLE.set_device_io_capabilities('KEYBOARD DISPLAY')))

        # print('start: ' + str(DONGLE.scan_start(scan_rep)))
        #
        # time.sleep(5)
        #
        # print('stop: ' + str(DONGLE.scan_stop()))

        time.sleep(2)

        DONGLE.close()

        DONGLE = None
