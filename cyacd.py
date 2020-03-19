"""
cfr inst-dir\Cypress\PSoC Creator\version\PSoC Creator\cybootloaderutils
"""

import string
import struct

class CYACD:
    def __init__(self):
        # CYDEV_CHIP_JTAG_ID
        self.sil_id = None

        self.sil_rev = None
        self.cks_type = None

        self.rows = []

    def _CyBtldr_ParseHeader(self, firstrow):
        x = struct.unpack('>IBB', firstrow)
        self.sil_id = x[0]
        self.sil_rev = x[1]
        self.cks_type = x[2]
        print('silicon id {:08X}'.format(self.sil_id))

    def _CyBtldr_ParseRowData(self, nextrow):
        checksum = nextrow[-1]
        nextrow.pop(-1)

        csum = 0
        for elem in nextrow:
            csum += elem
        csum = 1 + ~csum
        csum &= 0xFF

        if checksum != csum:
            return {}

        arrayId, rowNum, size = struct.unpack('>BHH', nextrow[:5])
        row = nextrow[5:]
        if len(row) != size:
            return {}

        csum = 0
        for elem in row:
            csum += elem
        csum = 1 + ((~csum) & 0xFF)
        csum &= 0xFF

        return {'arrayId': arrayId, 'rowNum': rowNum, 'checksum': csum, 'row': row}

    def _convert(self, char):
        if char in string.digits:
            return ord(char) - ord('0')
        else:
            char = char.upper()
            if char in string.hexdigits:
                return ord(char) - ord('A') + 10
        return 0

    def _bytes_from_char(self, a_row):
        a_row = a_row.strip('\n')

        res = bytearray()
        while len(a_row) >= 2:
            msb = self._convert(a_row[0])
            lsb = self._convert(a_row[1])
            val = (msb << 4) + lsb
            res.append(val)
            a_row = a_row[2:]
        return res

    def load(self, filename):
        with open(filename, 'rt') as ing:
            # first row
            ur = ing.readline()
            ba = self._bytes_from_char(ur)
            self._CyBtldr_ParseHeader(ba)

            while True:
                ur = ing.readline()
                if not any(ur):
                    break

                # remove starting :
                ba = self._bytes_from_char(ur[1:])

                # next row
                rd = self._CyBtldr_ParseRowData(ba)
                if not any(rd):
                    self.rows = []
                    break

                self.rows.append(rd)


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('I need the cyacd file name')
    else:
        cyacd = CYACD()

        cyacd.load(sys.argv[1])

        print(cyacd.rows)

