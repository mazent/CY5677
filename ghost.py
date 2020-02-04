"""
Manages ghost devices
"""

import time
import struct

import CY567x
import scan_util
import utili
import privacy as prv


FAKE_SECRET = bytes([
    0x0F, 0x82, 0x97, 0x5A, 0xD1, 0x98, 0xE0, 0xC7,
    0x9B, 0x2E, 0x1D, 0x1A, 0xC4, 0x35, 0xBF, 0x6E,
    0x0D, 0x7D, 0xDA, 0xF4, 0x8D, 0x7F, 0x13, 0x6A,
    0x3C, 0x32, 0xEF, 0x30, 0x46, 0x7C, 0xD6, 0xB7,
    0x88, 0x08, 0x5E, 0xD0, 0xBA, 0x0F, 0x86, 0x30,
    0x2C, 0xF8, 0x22, 0x2C, 0x46, 0x19, 0x89, 0xF8,
    0xE7, 0xCE, 0xAC, 0xBF, 0x98, 0xDD, 0xFA, 0x2A,
    0xD8, 0x29, 0xFE, 0x83, 0xDD, 0x3C, 0xCE, 0x71
])

CYBLE_SERVICE_AUTHOR_CHAR_HANDLE = 0x0015
CYBLE_SERVICE_WDOG_CHAR_HANDLE = 0x0018


class GHOST(CY567x.CY567x):
    """
    Knows ghost's commands
    """

    def __init__(self, porta=None):
        self.response = None
        self.authReq = False
        self.pairReq = False

        self.priv = None

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

    def find(self, to=3):
        """
        find ghosts
        :return: dict
        """
        self.scan_list = {}
        if self.scan_start():
            time.sleep(to)
            self.scan_stop()
        return self.scan_list

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

    def scan_progress_cb(self, adv):
        sr = scan_util.scan_report(adv)
        if sr['adv_type'] != 'Connectable undirected advertising':
            return

        adv = scan_util.scan_advertise(sr['data'])
        for elem in adv:
            if elem[0] != 'srv128':
                continue

            if elem[1] == '4A7A3045-BCD8-4ACA-B5AE-95FB82EEB222':
                print(sr['bda'] + ' {} dB'.format(sr['rssi']))
                self.scan_list[sr['bda']] = sr['rssi']

    def gap_auth_req_cb(self, ai):
        self.authReq = True

    def gap_passkey_entry_request_cb(self):
        self.pairReq = True

    def gattc_handle_value_ntf_cb(self, crt, ntf):
        print('crt={:04X}'.format(crt))
        if crt == CYBLE_SERVICE_AUTHOR_CHAR_HANDLE:
            challenge = self.priv.decrypt(ntf)
            if challenge is not None:
                pt = bytearray(self.mio)
                bc = challenge[6:]
                for elem in bc:
                    elem = (~elem) & 0xFF
                    pt.append(elem)
                self.response = self.priv.crypt(pt)


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
    DISPO = GHOST()

    if DISPO.is_ok():
        try:
            MAC = None

            dispi = DISPO.find()
            for dispo in dispi:
                print('trovato ' + dispo + ' {} dB'.format(dispi[dispo]))
                if MAC is None:
                    MAC = dispo

            if MAC is None:
                raise utili.Problema('no disp')

            pk = DISPO.compute_passkey(MAC, FAKE_SECRET)
            print('passkey={:06d}'.format(pk))

            if not DISPO.connect(MAC):
                raise utili.Problema('err connect')
            print('connesso')

            while not DISPO.authReq:
                time.sleep(.1)

            mtu = DISPO.exchange_gatt_mtu_size(MTU)
            if mtu == 0:
                raise utili.Problema('err mtu')
            print('mtu {}'.format(mtu))

            if not DISPO.initiate_pairing_request():
                raise utili.Problema('err pair req')

            while not DISPO.pairReq:
                time.sleep(.1)

            if not DISPO.pairing_passkey(pk):
                raise utili.Problema('err passkey')

            while DISPO.response is None:
                time.sleep(.1)

            if not DISPO.write_characteristic_value(
                    CYBLE_SERVICE_AUTHOR_CHAR_HANDLE, DISPO.response):
                raise utili.Problema('err autor')

            if not DISPO.write_characteristic_value(CYBLE_SERVICE_WDOG_CHAR_HANDLE, bytearray([0]*5)):
                raise utili.Problema('err write')

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        DISPO.disconnect()
        DISPO.close()
