"""
Manages ghost devices
"""

import time
import struct
import queue

import crcmod

import CY567x
import scan_util
import utili
import privacy as prv


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

srv_conf = 'C18594D9-DFF5-4552-89F8-0F2940D1E32D'
srv_norm = '4A7A3045-BCD8-4ACA-B5AE-95FB82EEB222'


# Verificare che siano uguali a quelle in BT_custom.h
# srv_norm
CYBLE_SERVICE_AUTHOR_CHAR_HANDLE = 0x0018
CYBLE_SERVICE_WDOG_CHAR_HANDLE = 0x001A
# srv_conf
CYBLE_CONFIG_AUTHOR_CHAR_HANDLE = 0x0012
CYBLE_CONFIG_CMD_CHAR_HANDLE = 0x0014


class GHOST_CONF:
    """
    collects commands valid only during CONF phase
    """

    def read_times(self, to=3):
        """
        send the command to read Tnp, Tp, Tall
        :param to: timeout
        :return: tuple or None
        """

    def write_times(self, Tnp, Tp, Tall, to=3):
        """
        send the command to write Tnp, Tp, Tall
        :param Tnp: see doc
        :param Tp: see doc
        :param Tall: see doc
        :param to: timeout
        :return: bool
        """

    def goto_NORM(self, to=3):
        """
        Set NORM as the next phase
        :param to: timeout
        :return: bool
        """

    def goto_PROD(self, to=3):
        """
        Set PROD as the next phase
        :param to: timeout
        :return: bool
        """


class GHOST(CY567x.CY567x, GHOST_CONF):
    """
    Knows ghost's commands
    """

    def __init__(self, porta=None):
        self.response = None
        self.authReq = False
        self.pairReq = False

        self.priv = None

        self.crc = crcmod.Crc(0x11021, 0xC681, False, 0x0000)
        self.rsp = queue.Queue()

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
        find the ghost with a specific serial number
        :param cp: serial number
        :param to: timeout
        :return: tuple bda (bytearray) + mode or None
        """
        srvdata = bytearray()

        fcrc = self.crc.new()
        fcrc.update(cp.encode('ascii'))
        cpcrc = fcrc.digest()
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
            rssi, mode = self.scan_list[dispo]
            print('trovato ' + dispo + ' {} dB '.format(rssi) + mode)
            return dispo, mode

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

    def authorize(self, car):
        """
        execute the challenge/response procedure
        :return:
        """
        chl = self.read_characteristic_value(car)
        if chl is None:
            return False

        challenge = self.priv.decrypt(chl)
        if challenge is None:
            return False

        pt = bytearray(self.mio)
        bc = challenge[6:]
        for _elem in bc:
            _elem = (~_elem) & 0xFF
            pt.append(_elem)
        response = self.priv.crypt(pt)

        return self.write_characteristic_value(
            car, response)

    def _create_command(self, cmd, prm=None):
        fcrc = self.crc.new()

        xxx = bytearray([cmd])
        if prm is not None:
            xxx += prm

        fcrc.update(xxx)
        xxx += fcrc.digest()

        print('comando: ' + utili.esa_da_ba(xxx, ' '))

        return xxx

    def _extract_response(self, ntf):
        fcrc = self.crc.new()

        fcrc.update(ntf)
        if fcrc.digest() == bytearray([0] * 2):
            rsp = {'cmd': ntf.pop(0), 'prm': ntf[:len(ntf) - 2]}

            return rsp

        return None

    def _cmd_void_void(self, char, cmd, to=3):
        msg = self._create_command(cmd)

        try:
            if not self.write_characteristic_value(char, msg):
                raise utili.Problema('? write_characteristic_value ?')

            _crt, ntf = self.rsp.get(True, to)
            if _crt != char:
                raise utili.Problema('? crt ?')

            rsp = self._extract_response(ntf)
            if rsp is None:
                raise utili.Problema('? rsp ?')

            if rsp['cmd'] != cmd:
                raise utili.Problema('? cmd ?')

            return True

        except (queue.Empty, utili.Problema) as err:
            if isinstance(err, utili.Problema):
                print(err)
            return False

    # ------ CONF ------------------------------------------------------------

    def read_times(self, to=3):
        cmd = self._create_command(0x8C)

        try:
            if not self.write_characteristic_value(
                    CYBLE_CONFIG_CMD_CHAR_HANDLE, cmd):
                raise utili.Problema('? write_characteristic_value ?')

            _crt, ntf = self.rsp.get(True, to)
            if _crt != CYBLE_CONFIG_CMD_CHAR_HANDLE:
                raise utili.Problema('? crt ?')

            rsp = self._extract_response(ntf)
            if rsp is None:
                raise utili.Problema('? rsp ?')

            cmd = rsp['cmd']
            if cmd != 0x8C:
                raise utili.Problema('? cmd ?')

            prm = rsp['prm']
            if len(prm) != 6:
                raise utili.Problema('? prm ?')

            return struct.unpack('<3H', prm)

        except (queue.Empty, utili.Problema) as err:
            if isinstance(err, utili.Problema):
                print(err)
            return None

    def write_times(self, Tnp, Tp, Tall, to=3):
        prm = struct.pack('<3H', Tnp, Tp, Tall)
        cmd = self._create_command(0x1A, prm=prm)

        try:
            if not self.write_characteristic_value(
                    CYBLE_CONFIG_CMD_CHAR_HANDLE, cmd):
                raise utili.Problema('? write_characteristic_value ?')

            _crt, ntf = self.rsp.get(True, to)
            if _crt != CYBLE_CONFIG_CMD_CHAR_HANDLE:
                raise utili.Problema('? crt ?')

            rsp = self._extract_response(ntf)
            if rsp is None:
                raise utili.Problema('? rsp ?')

            cmd = rsp['cmd']
            if cmd != 0x1A:
                raise utili.Problema('? cmd ?')

            return True

        except (queue.Empty, utili.Problema) as err:
            if isinstance(err, utili.Problema):
                print(err)
            return False

    def goto_NORM(self, to=3):
        return self._cmd_void_void(CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xC0, to=to)

    def goto_PROD(self, to=3):
        return self._cmd_void_void(CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xD2, to=to)

    def scan_progress_cb(self, adv):
        sr = scan_util.scan_report(adv)
        if sr['adv_type'] != 'Connectable undirected advertising':
            return

        adv = scan_util.scan_advertise(sr['data'])
        for _elem in adv:
            if _elem[0] != 'srvd128':
                continue

            if _elem[1] in (srv_norm, srv_conf):
                srvdata = _elem[2]
                if srvdata == self.srvdata:
                    print(sr['bda'] + ' {} dB '.format(sr['rssi']))
                    self.scan_list[sr['bda']] = \
                        (sr['rssi'],
                         'NORM' if _elem[1] == srv_norm else 'CONF')

    def gap_auth_req_cb(self, ai):
        self.authReq = True

    def gap_passkey_entry_request_cb(self):
        self.pairReq = True

    def gattc_handle_value_ntf_cb(self, crt, ntf):
        print('ntf crt={:04X}'.format(crt))
        self.rsp.put_nowait((crt, ntf))


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
            elem = ghost.find(PRD)
            if elem is None:
                raise utili.Problema('no disp')

            MAC = elem[0]
            MODE = elem[1]

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

            crt_ = CYBLE_SERVICE_AUTHOR_CHAR_HANDLE
            if MODE == 'CONF':
                crt_ = CYBLE_CONFIG_AUTHOR_CHAR_HANDLE
            if not ghost.authorize(crt_):
                raise utili.Problema('err autor')

            if MODE == 'CONF':
                tempi = ghost.read_times()
                if tempi is None:
                    raise utili.Problema('err read_times')
                print(
                    'Tnp={} Tp={} Tall={}'.format(
                        tempi[0], tempi[1], tempi[2]))

                if not ghost.write_times(tempi[0], tempi[1], tempi[2]):
                    raise utili.Problema('err write_times')
                print('write_times OK')

                if not ghost.goto_NORM():
                    raise utili.Problema('err goto_NORM')
                print('goto_NORM OK')

            # if not ghost.write_characteristic_value(
            #         CYBLE_SERVICE_WDOG_CHAR_HANDLE, bytearray([0])):
            #     raise utili.Problema('err write')

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        ghost.disconnect()
        ghost.close()
