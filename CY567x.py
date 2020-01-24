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


class _COMMAND:

    def __init__(self, cmd, prm=None):
        self.cod = cmd
        self.prm = prm
        self.resul = queue.Queue()

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


class CY567x(threading.Thread):
    """
    manages two cypress dongles: CY5677 and CY5670 (old)
    """
    QUIT = 0xE5C1
    ABORT_CURRENT_COMMAND = 0xACC0
    Cmd_Init_Ble_Stack_Api = 0xFC07

    def __init__(self, BAUD=BAUD_CY5677, poll=0.1, porta=None):
        #self.scan_cb = None
        self.poll = poll
        self.proto = {
            'rx': prt.PROTO_RX(),
            'tx': prt.PROTO_TX()
        }

        self.events = {
            cc.EVT_COMMAND_STATUS: self._evt_command_status,
            cc.EVT_COMMAND_COMPLETE: self._evt_command_complete
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

            self.connection = {
                'mtu': 23,
                'cyBle_connHandle': None
            }

            self.curr_cmd = None

            self.cmd_queue = queue.Queue()

            # # mando io il comando che inizializza
            # self.coda_cmd.put_nowait((Cmd_Init_Ble_Stack_Api, None))

            # posso girare
            threading.Thread.__init__(self)
            self.start()

        except serial.SerialException as err:
            print(err)
            self.uart = None

    def __del__(self):
        print('del')
        self.close()

    def _evt_command_status(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        print('EVT_COMMAND_STATUS: cmd={:04X} stt={}'.format(cmd, status))

    def _evt_command_complete(self, prm):
        cmd, status = struct.unpack('<2H', prm)
        print('EVT_COMMAND_COMPLETE: cmd={:04X} stt={}'.format(cmd, status))
        if self.curr_cmd is None:
            print('no cmd waiting')
        elif self.curr_cmd.cod == cmd:
            self.curr_cmd.resul.put_nowait(status == 0)
            self.curr_cmd = None
        else:
            print('wrong cmd')

    def _send_command_and_wait(self, cod, prm=None):
        # send
        cmd = _COMMAND(cod, prm)
        self.cmd_queue.put_nowait(cmd)

        # wait
        res = cmd.result()
        if res is None:
            # abort
            self.cmd_queue.put_nowait(_COMMAND(self.ABORT_CURRENT_COMMAND))
            return False

        return res

    def run(self):
        print('nasco')
        while True:
            # any command?
            try:
                # cmd = _COMMAND
                cmd = self.cmd_queue.get(True, self.poll)

                if cmd.cod == self.QUIT:
                    break

                if cmd.cod == self.ABORT_CURRENT_COMMAND:
                    self.curr_cmd = None
                    break

                if self.curr_cmd is None:
                    self.curr_cmd = cmd
                    msg = self.proto['tx'].compose(cmd.cod, cmd.prm)

                    print('IRP_MJ_WRITE Data: ' + utili.esa_da_ba(msg, ' '))
                    self.uart.write(msg)
                else:
                    # busy
                    self.cmd_queue.put_nowait(cmd)
            except (queue.Empty, KeyError) as err:
                if isinstance(err, KeyError):
                    print('comando sconosciuto')

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

            self.cmd_queue.put_nowait(ktt)

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


if __name__ == '__main__':
    DONGLE = CY567x()
    if not DONGLE.is_ok():
        print('uart error')
    else:
        print(DONGLE.init_ble_stack())

        DONGLE.close()

        DONGLE = None
