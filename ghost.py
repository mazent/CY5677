"""
Manages ghost devices
"""

import time
import struct

import CY567x
import scan_util
import utili
import privacy as prv
import crcmod


FAKE_SECRET = bytes([
    0xA3, 0xED, 0x47, 0x19, 0xDF, 0x11, 0xB6, 0x8E,
    0x22, 0x66, 0x6A, 0x83, 0x9C, 0x8C, 0x38, 0x6F,
    0x4D, 0xC0, 0x30, 0xFB, 0xBF, 0x41, 0xFA, 0xFA,
    0xDC, 0x02, 0x03, 0xAD, 0x5A, 0x88, 0x75, 0xD3,
    0x43, 0x40, 0x33, 0xD2, 0xEE, 0x9B, 0x24, 0x8A,
    0xA0, 0x51, 0x26, 0x33, 0xD0, 0x6B, 0x70, 0x39,
    0xDA, 0xB5, 0xF9, 0xE5, 0x9B, 0x86, 0x13, 0x2F,
    0x2E, 0xB0, 0xA6, 0x12, 0xA1, 0x1B, 0xEB, 0xAF
])

# Verificare che siano uguali a quelle in BT_custom.h
CYBLE_SERVICE_AUTHOR_CHAR_HANDLE = 0x0018
CYBLE_SERVICE_WDOG_CHAR_HANDLE = 0x001A

class GHOST(CY567x.CY567x):
    """
    Knows ghost's commands
    """

    def __init__(self, porta=None):
        self.response = None
        self.authReq = False
        self.pairReq = False

        self.priv = None

        self.srvdata = None
        self.scan_list = []

        CY567x.CY567x.__init__(self, porta=porta)

        self.mio = None

        try:
            if not self.is_ok():
                raise utili.Problema('not OK')

            if not self.init_ble_stack():
                raise utili.Problema('err init')

            if not self.set_device_io_capabilities('KEYBOARD DISPLAY'):
                raise utili.Problema('err capa')

            if not self.set_local_device_security('3'):
                raise utili.Problema('err security')

            mio = self.my_address()
            if mio is None:
                raise utili.Problema('err bdaddr')

            self.mio = mio
            print('io sono ' + utili.str_da_mac(mio))
        except utili.Problema as err:
            print(err)

    def find(self, cp, to=3):
        """
        find ghosts
        :return: bda (bytearray) or None
        """
        srvdata = bytearray()

        crc = crcmod.Crc(0x11021, 0xC681, False, 0x0000)
        crc.update(cp.encode('ascii'))
        cpcrc = crc.digest()
        srvdata.append(cpcrc[1])
        srvdata.append(cpcrc[0])

        prog = int(cp[5:])
        tmp = bytearray(struct.pack('<I', prog))
        del tmp[-1]

        srvdata += tmp
        print('srvdata: ' + utili.esa_da_ba(srvdata, ' '))

        self.srvdata = srvdata

        self.scan_list = {}
        if self.scan_start():
            time.sleep(to)
            self.scan_stop()

        for dispo in self.scan_list:
            print('trovato ' + dispo + ' {} dB'.format(self.scan_list[dispo]))
            return dispo

        return None

    def compute_passkey(self, bda, secret):
        """
        returns the passkey for a ghost with the specified mac and secret
        :param bda: string (aka mac address)
        :param secret: bytes
        :return: integer
        """
        self.priv = prv.PRIVACY(secret)
        x = self.priv.hash(utili.mac_da_str(bda))
        pqb = struct.unpack('<I', x[:4])
        return pqb[0] % 1000000

    def connect(self, bda, public=False):
        return super().connect(bda, public)

    def authorize(self):
        chl = self.read_characteristic_value(CYBLE_SERVICE_AUTHOR_CHAR_HANDLE)
        if chl is None:
            return False

        challenge = self.priv.decrypt(chl)
        if challenge is None:
            return False

        pt = bytearray(self.mio)
        bc = challenge[6:]
        for elem in bc:
            elem = (~elem) & 0xFF
            pt.append(elem)
        response = self.priv.crypt(pt)

        return self.write_characteristic_value(
            CYBLE_SERVICE_AUTHOR_CHAR_HANDLE, response)

    def scan_progress_cb(self, adv):
        sr = scan_util.scan_report(adv)
        if sr['adv_type'] != 'Connectable undirected advertising':
            return

        adv = scan_util.scan_advertise(sr['data'])
        for elem in adv:
            if elem[0] != 'srvd128':
                continue

            if elem[1] == '4A7A3045-BCD8-4ACA-B5AE-95FB82EEB222':
                srvdata = elem[2]
                if srvdata == self.srvdata:
                    print(sr['bda'] + ' {} dB '.format(sr['rssi']))
                    self.scan_list[sr['bda']] = sr['rssi']

    def gap_auth_req_cb(self, ai):
        self.authReq = True

    def gap_passkey_entry_request_cb(self):
        self.pairReq = True

    # def gattc_handle_value_ntf_cb(self, crt, ntf):
    #     print('crt={:04X}'.format(crt))
    #     if crt == CYBLE_SERVICE_AUTHOR_CHAR_HANDLE:
    #         challenge = self.priv.decrypt(ntf)
    #         if challenge is not None:
    #             pt = bytearray(self.mio)
    #             bc = challenge[6:]
    #             for elem in bc:
    #                 elem = (~elem) & 0xFF
    #                 pt.append(elem)
    #             self.response = self.priv.crypt(pt)


DESCRIZIONE = \
    '''
    prova della demo
    '''

if __name__ == '__main__':

    import argparse

    # argomenti
    argom = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=DESCRIZIONE)
    #argom.add_argument('mac', help="L'indirizzo del dispositivo (xx:yy:..ww)")
    argom.add_argument(
        '--mtu',
        type=int,
        default=512,
        help='mtu da utilizzare (pred: 512)')
    # argom.add_argument(
    #     '--dim',
    #     type=int,
    #     default=0,
    #     help='dimensione dati aggiuntivi (pred: 0)')
    # argom.add_argument(
    #     '--num',
    #     type=int,
    #     default=0,
    #     help='numero di pacchetti da spedire (pred: 0 = infiniti)')
    arghi = argom.parse_args()

    #MAC = arghi.mac
    MTU = arghi.mtu
    # DIM = arghi.dim
    # NUM = arghi.num
    # criterio = lambda cnt, lim: True
    # if NUM:
    #     criterio = lambda cnt, lim: cnt < lim

    # test
    ghost = GHOST()

    PRD = 'XXXpy359687'

    if ghost.is_ok():
        try:
            MAC = ghost.find(PRD)
            if MAC is None:
                raise utili.Problema('no disp')

            pk = ghost.compute_passkey(MAC, FAKE_SECRET)
            print('passkey={:06d}'.format(pk))

            if not ghost.connect(MAC):
                raise utili.Problema('err connect')
            print('connesso')

            while not ghost.authReq:
                time.sleep(.1)

            mtu = ghost.exchange_gatt_mtu_size(MTU)
            if mtu == 0:
                raise utili.Problema('err mtu')
            print('mtu {}'.format(mtu))

            if not ghost.initiate_pairing_request():
                raise utili.Problema('err pair req')

            while not ghost.pairReq:
                time.sleep(.1)

            if not ghost.pairing_passkey(pk):
                raise utili.Problema('err passkey')

            # while DISPO.response is None:
            #     time.sleep(.1)

            if not ghost.authorize():
                raise utili.Problema('err autor')

            if not ghost.write_characteristic_value(CYBLE_SERVICE_WDOG_CHAR_HANDLE, bytearray([0])):
                raise utili.Problema('err write')

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        ghost.disconnect()
        ghost.close()
