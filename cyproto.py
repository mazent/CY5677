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

    def __init__(self, nome, primo, secondo):
        # class identifier
        self.name = nome
        # byte headers
        self.first = primo
        self.second = secondo

        # messages are stored here (without header)
        self.msg_list = []

        # protocol state
        self.partial = bytearray()
        self.state = 'idle'
        self.dim = -1

    def reinit(self):
        """
        Come back to the initial state
        :return: n.a.
        """
        self.partial = bytearray()
        self.dim = -1
        self.state = 'idle'

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

    def examine(self, questi):
        """
        inspect new data and extract messages
        :param questi: bytearray of data collected from serial port
        :return: n.a. (call get_msg)
        """
        for cosa in questi:
            if cosa == self.first:
                # start of header
                self.state = 'header'
            elif cosa == self.second:
                # end of header
                if self.state == 'header':
                    # new message
                    if len(self.partial):
                        # add the previous to the list
                        self.msg_list.append(bytearray(self.partial))
                        self.reinit()
                    self.state = 'msg'
                else:
                    # add to the current message
                    self.partial.append(cosa)
            else:
                # other
                if self.state == 'header':
                    # previous byte was not header's start
                    self.partial.append(self.first)
                    self.state = 'idle'
                self.partial.append(cosa)

                self.check_len()

    def check_len(self):
        """
        message lenght is in different positions: override this to catch messages
        :return: n.a.
        """

    def msg_to_string(self, cosa):
        """
        convert the message to a human readable string: override this
        :param cosa: message
        :return: string
        """


class PROTO_RX(PROTO):
    """
    specialization for messages received from CY5677
    """

    def __init__(self):
        PROTO.__init__(self, 'RX', 0xBD, 0xA7)

    def check_len(self):
        if self.dim < 0:
            # calculate dimension
            if len(self.partial) == 4:
                tot, _ = struct.unpack('<2H', self.partial[:4])
                self.dim = tot + 2

        if self.dim == len(self.partial):
            # got it!
            self.msg_list.append(bytearray(self.partial))

            self.reinit()
        else:
            pass

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
                print(self.name +
                      ' ERR DIM {:04X}[{} != {}]: '.format(evn, tot, len(
                          prm)) + utili.esa_da_ba(prm, ' '))
            else:
                msg['evn'] = evn
                msg['prm'] = prm

                print(
                    self.name +
                    ' {:04X}[{}]: '.format(evn, tot) +
                    utili.esa_da_ba(prm, ' '))
        else:
            print(self.name + ' ????: ' + utili.esa_da_ba(cosa, ' '))
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
                    tot, len(prm)) + '\n\t' + utili.esa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                    utili.esa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.esa_da_ba(cosa, ' ')

        return risul


class PROTO_TX(PROTO):
    """
    specialization for messages sent to CY5677
    """

    _HEADER_CMD = 0x5943

    def __init__(self):
        PROTO.__init__(self, 'TX', 0x43, 0x59)

    def check_len(self):
        if self.dim < 0:
            # compute dimension
            if len(self.partial) == 4:
                _, tot = struct.unpack('<2H', self.partial[:4])
                self.dim = tot + 4

        if self.dim == len(self.partial):
            # got it!
            self.msg_list.append(bytearray(self.partial))

            self.reinit()
        else:
            pass

    def msg_to_string(self, cosa):
        risul = self.name + ' '
        if len(cosa) >= 4:
            msg, tot = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]

            risul += quale_comando(msg) + ' '

            if tot != len(prm):
                risul += 'ERR DIM [{} != {}]: '.format(tot, len(
                    prm)) + '\n\t' + utili.esa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                    utili.esa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.esa_da_ba(cosa, ' ')

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
