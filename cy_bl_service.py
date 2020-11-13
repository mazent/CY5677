import queue
import struct


def _bl_csum(pckh):
    csum = 0
    for _pckh in pckh:
        csum += _pckh
    csum = (~csum) & 0xFFFF
    csum += 1

    return csum & 0xFFFF


class CY_BL_SERVICE:
    """
    implements cypress bootloader service commands
    """

    # cysmart uses 137
    DIM = 137

    # Start of Packet
    SOP = 0x01

    # End of Packet
    EOP = 0x17

    COMMAND_CHECKSUM = 0x31
    COMMAND_REPORT_SIZE = 0x32
    COMMAND_DATA = 0x37
    COMMAND_ENTER = 0x38
    COMMAND_PROGRAM = 0x39
    COMMAND_VERIFY = 0x3A
    COMMAND_EXIT = 0x3B

    def _reset(self, coda):
        pass

    def write_characteristic_value(self, crt, dati, to=5):
        """
        this method must be implemented, e.g. by CY567x
        """
        # pylint: disable=unused-argument,no-self-use
        return False

    def write_char_best(self, crt, dati, to=5):
        """
        this method must be implemented, e.g. by CY567x
        """
        # pylint: disable=unused-argument,no-self-use
        return False

    def __init__(self):
        self.blc = None
        self.sincro = {}

    def _bl_pkt_trail(self, pkt):
        return struct.pack('<HB', _bl_csum(pkt), self.EOP)

    def _bl_get_msg(self, pkt):
        if len(pkt) < 7:
            return None
        if pkt[0] != self.SOP:
            return None
        if pkt[-1] != self.EOP:
            return None
        csump = struct.unpack('<H', pkt[-3:-1])[0]
        csumc = _bl_csum(pkt[:-3])
        if csumc != csump:
            return None
        msg = {'code': pkt[1], 'data': pkt[4:-3]}
        return msg

    def bl_enter(self, blc, to=10):
        """
        Enter the bootloader
        :param blc: from discover_all_characteristics {'attr', 'prop', 'value', 'uuid128'}
        :param to: timeout
        :return: dict
        """
        self.blc = blc['value']

        msg = struct.pack('<BBH', self.SOP, self.COMMAND_ENTER, 0)
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_characteristic_value(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return None
                if msg['code'] != 0:
                    return None
                val = struct.unpack('<I4B', msg['data'])
                return {
                    'SiliconId': val[0],
                    'Revision': val[1],
                    'Version': '{}.{}.{}'.format(val[2], val[3], val[4])
                }
            except queue.Empty:
                pass

        return None

    def bl_flash_size(self, to=10):
        """
        Report the programmable portions of flash (in rows, 256 B)
        :param to: timeout
        :return: dict
        """
        if self.blc is None:
            return None

        msg = struct.pack('<BBHB', self.SOP, self.COMMAND_REPORT_SIZE, 1, 0)
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_characteristic_value(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return None
                if msg['code'] != 0:
                    return None
                val = struct.unpack('<2H', msg['data'])
                return {'first': val[0], 'tot': val[1]}
            except queue.Empty:
                pass

        return None

    def bl_data(self, data, dim=0, to=10):
        """
        Queue up a block of data for programming
        :param data: bytearray
        :param dim: to send
        :param to: timeout
        :return: bool
        """
        if self.blc is None:
            return False

        if dim == 0:
            dim = self.DIM

        msg = struct.pack('<BBH', self.SOP, self.COMMAND_DATA, dim)
        msg += data[:dim]
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_char_best(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return False
                if msg['code'] != 0:
                    return False
                return True
            except queue.Empty:
                pass

        return False

    def bl_program(self, aid, rown, data=None, to=20):
        """
        Program the specified row
        :param aid: array id
        :param rown: row number
        :param data: to program
        :param to: timeout
        :return: bool
        """
        if self.blc is None:
            return False

        dim = 3
        if data is not None:
            dim += len(data)

        msg = struct.pack('<BBHBH', self.SOP, self.COMMAND_PROGRAM, dim, aid,
                          rown)
        if data is not None:
            msg += data[:dim]
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_char_best(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return False
                if msg['code'] != 0:
                    return False
                return True
            except queue.Empty:
                pass

        return False

    def bl_verify(self, aid, rown, to=5):
        """
        Compute flash row checksum for verification
        :param aid:
        :param rown:
        :param to:
        :return: checksum
        """
        if self.blc is None:
            return None

        msg = struct.pack('<BBHBH', self.SOP, self.COMMAND_VERIFY, 3, aid,
                          rown)
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_characteristic_value(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return None
                if msg['code'] != 0:
                    return None
                return struct.unpack('<B', msg['data'])[0]
            except queue.Empty:
                pass

        return None

    def bl_validate(self, to=10):
        """
        Verify the checksum for the bootloadable project
        :param to: timeout
        :return: bool
        """
        if self.blc is None:
            return False

        msg = struct.pack('<BBH', self.SOP, self.COMMAND_CHECKSUM, 0)
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_characteristic_value(self.blc, msg, to=to):
            try:
                blr = self.sincro['blr'].get(True, to)
                msg = self._bl_get_msg(blr)
                if msg is None:
                    return False
                if msg['code'] != 0:
                    return False
                val = struct.unpack('<B', msg['data'])[0]
                return val == 1
            except queue.Empty:
                pass

        return False

    def bl_exit(self, to=5):
        """
        Exits the bootloader & resets the chip
        :param to:
        :return: bool
        """
        if self.blc is None:
            return False

        msg = struct.pack('<BBH', self.SOP, self.COMMAND_EXIT, 0)
        msg += self._bl_pkt_trail(msg)

        return self.write_characteristic_value(self.blc, msg, to=to)
