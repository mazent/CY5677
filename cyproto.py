"""
Collects classes for the CY5677 dongle
"""
import struct

import utili
from cycost import quale_evento, quale_comando


class PROTO:
    """
    Knows the communication protocol of CY5677 dongle
    """

    def _print(self, msg):
        if self.can_print:
            print(msg)

    def __init__(self, nome, primo, secondo):
        self.can_print = False

        # class identifier
        self.name = nome
        # byte headers
        self.first = primo
        self.second = secondo

        # messages are stored here (without header)
        self.msg_list = []

        # protocol state
        self.partial = bytearray()

        self.dim = -1
        self.stati = {
            0: self._stato_0,
            1: self._stato_1,
            2: self._stato_2,
            3: self._stato_3
        }
        self.stato = 0

    def _stato_0(self, rx):
        if rx == self.first:
            self.stato = 1

    def _stato_1(self, rx):
        if rx == self.second:
            self.stato = 2
        else:
            if len(self.partial):
                self._print(
                    '_stato_1 elimino {}'.format(
                        utili.stringa_da_ba(
                            self.partial, '-')))
            self.reinit()

    def _stato_2(self, rx):
        self.partial.append(rx)
        if len(self.partial) == 2:
            self.dim = 2 + struct.unpack('<H', self.partial)[0]
            self.stato = 3

    def _stato_3(self, rx):
        self.partial.append(rx)
        if len(self.partial) == self.dim:
            self.dim = -1
            self.check_packet(False)

    def _dim_pkt(self):
        tot, _ = struct.unpack('<2H', self.partial[:4])
        return tot + 2

    def who_are_you(self):
        """
        Make an educated guess
        :return: the name
        """
        return self.name

    def get_msg(self):
        """
        retrieve a message if present
        :return: a bytearray or None
        """
        if any(self.msg_list):
            return self.msg_list.pop(0)

        return None

    def msg_to_string(self, cosa):
        """
        convert the message to a human readable string: override this
        :param cosa: message
        :return: string
        """

    # Packet analysis
    def reinit(self, start=False):
        """
        Come back to the initial state
        :return: n.a.
        """
        self.partial = bytearray()
        if start:
            # the first byte is arrived
            self.stato = 1
        else:
            self.stato = 0

    def check_packet(self, start=False):
        def empty_partial():
            # a new packet starts
            if len(self.partial):
                self._print('scarto ' + utili.stringa_da_ba(self.partial, '-'))
                self.reinit(True)

        if len(self.partial) >= 4:
            tot = self._dim_pkt()
            if tot == len(self.partial):
                # got it!
                self.msg_list.append(bytearray(self.partial))

                self.reinit(start)
            elif start:
                empty_partial()
            else:
                pass
        elif start:
            empty_partial()

    def examine(self, questi):
        for cosa in questi:
            self.stati[self.stato](cosa)

        self.check_packet()


class PROTO_RX(PROTO):
    """
    specialization for messages received from CY5677
    """

    def __init__(self):
        PROTO.__init__(self, 'RX', 0xBD, 0xA7)

    def decompose(self, cosa):
        """
        extract event and parameters from a message
        :param cosa: bytearray (message)
        :return: dictionary with 'evn', 'prm' (or empty)
        """
        msg = {}
        if len(cosa) >= 4:
            tot, evn = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]
            tot -= 2

            if tot != len(prm):
                self._print(self.name +
                            ' ERR DIM {:04X}[{} != {}]: '.format(evn, tot, len(
                                prm)) + utili.stringa_da_ba(prm, ' '))
            else:
                msg['evn'] = evn
                msg['prm'] = prm

                self._print(
                    self.name +
                    ' {:04X}[{}]: '.format(evn, tot) +
                    utili.stringa_da_ba(prm, ' '))
        else:
            self._print(self.name + ' ????: ' + utili.stringa_da_ba(cosa, ' '))
        return msg

    def msg_to_string(self, cosa):
        risul = self.name + ' '
        if len(cosa) >= 4:
            tot, msg = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]
            tot -= 2

            risul += quale_evento(msg) + ' '

            if tot != len(prm):
                risul += 'ERR DIM [{} != {}]: '.format(
                    tot, len(prm)) + '\n\t' + utili.stringa_da_ba(prm, ' ')
            elif 'EVT_COMMAND_STATUS' in risul or 'EVT_COMMAND_COMPLETE' in risul:
                cmd = struct.unpack('<H', prm[:2])[0]
                risul += '{:04X} [{}]: '.format(cmd, tot) + '\n\t' + \
                         utili.stringa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                         utili.stringa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.stringa_da_ba(cosa, ' ')

        return risul


class PROTO_TX(PROTO):
    """
    specialization for messages sent to CY5677
    """

    _HEADER_CMD = 0x5943

    def __init__(self):
        PROTO.__init__(self, 'TX', 0x43, 0x59)

    def _stato_2(self, rx):
        self.partial.append(rx)
        if len(self.partial) == 2:
            self.stato = 3

    def _stato_3(self, rx):
        self.partial.append(rx)
        if len(self.partial) == 4:
            self.dim = struct.unpack('<H', self.partial[2:])[0]
        elif len(self.partial) == self.dim:
            self.dim = -1
            self.check_packet(False)

    def _dim_pkt(self):
        _, tot = struct.unpack('<2H', self.partial[:4])
        return tot + 4

    def msg_to_string(self, cosa):
        risul = self.name + ' '
        if len(cosa) >= 4:
            msg, tot = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]

            risul += quale_comando(msg) + ' '

            if tot != len(prm):
                risul += 'ERR DIM [{} != {}]: '.format(tot, len(
                    prm)) + '\n\t' + utili.stringa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                         utili.stringa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.stringa_da_ba(cosa, ' ')

        return risul

    def compose(self, cmd):
        """
        create a command to be sent to the dongle
        :param cmd: dict with parameters
        :return: bytearray
        """
        dim = 0
        if cmd['prm'] is not None:
            dim = len(cmd['prm'])
        msg = struct.pack('<3H', self._HEADER_CMD, cmd['cod'], dim)
        if dim:
            msg += cmd['prm']

        return msg
