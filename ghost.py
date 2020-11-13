"""
Manages ghost devices
"""

import struct
import queue
import threading
import time

import crcmod

import CY567x
import scan_util
import cy_bl_service as bl
import utili
import privacy as prv

srv_conf = 'C18594D9-DFF5-4552-89F8-0F2940D1E32D'
srv_norm = '4A7A3045-BCD8-4ACA-B5AE-95FB82EEB222'

# Verificare che siano uguali a quelle in BT_custom.h
# srv_norm
CYBLE_SERVICE_AUTHOR_CHAR_HANDLE = 0x0018
CYBLE_SERVICE_CMD_CHAR_HANDLE = 0x001A
# srv_conf
CYBLE_CONFIG_AUTHOR_CHAR_HANDLE = 0x0012
CYBLE_CONFIG_CMD_CHAR_HANDLE = 0x0014
CYBLE_CONFIG_CMD_CLIENT_CHARACTERISTIC_CONFIGURATION_DESC_HANDLE = 0x0015


def nsp_from(service_data):
    """
    retituisce il numero di serie del prodotto dal service data
    :param service_data: bytearray
    :return: string
    """
    # lettere e numeri compressi
    cp = struct.unpack('<I', service_data[:4])[0]
    _nsp = ''
    for _ in range(5):
        x = cp & 0x3F
        if x < 10:
            _nsp = _nsp + chr(x + ord('0'))
        elif x <= 35:
            _nsp = _nsp + chr(x - 10 + ord('A'))
        else:
            _nsp = _nsp + chr(x - 36 + ord('a'))
        cp >>= 6
    # numero progressivo
    np = bytearray(service_data[4:])
    np.append(0)
    prog = struct.unpack('<I', np)[0]
    return _nsp + '{:06d}'.format(prog)


def service_data_from(numserprod):
    """
    calcola il service data a partire dal numero di serie del prodotto
    :param numserprod: string
    :return: bytearray
    """
    tmp = 0
    sposta = 0
    pc = numserprod[:5]
    for _elem in pc:
        val = 0
        if _elem.isdigit():
            val = int(_elem)
        elif _elem.isupper():
            val = ord(_elem) - ord('A')
            val += 10
        elif _elem.islower():
            val = ord(_elem) - ord('a')
            val += 36
        else:
            pass
        tmp += val << sposta
        sposta += 6
    gsd = struct.pack('<I', tmp)

    # seguono sei cifre decimali -> bastano 3 byte
    prog = int(numserprod[5:])
    tmp = bytearray(struct.pack('<I', prog))
    del tmp[-1]
    gsd += tmp

    return gsd


class GHOST_COMMAND:
    """
    collects commands
    """

    def cmd_void_void(self, char, cmd, to=3):
        # pylint: disable=R0201,W0613
        """
        execute a command without data to send and receive
        pylint is disabled because of overriding
        :param char: handle
        :param cmd: opcode
        :param to: timeout
        :return: bool
        """
        return False

    def cmd_void_rsp(self, char, cmd, dim=None, to=3):
        # pylint: disable=R0201,W0613
        """
        execute a command without data to send but with data to receive
        pylint is disabled because of overriding
        :param char: handle
        :param cmd: opcode
        :param to: timeout
        :return: bytearray / None
        """
        return bytearray()

    def cmd_prm_void(self, char, cmd, prm, to=3):
        # pylint: disable=R0201,W0613
        """
        execute a command with data to send but nothing to receive
        pylint is disabled because of overriding
        :param char: handle
        :param cmd: opcode
        :param prm: bytearray
        :param to: timeout
        :return: bool
        """
        return False

    def enable_notify_indicate(self, char):
        # pylint: disable=R0201,W0613
        """
        enables notifications and indications
        :return: bool
        """
        return False


class GHOST_NORM(GHOST_COMMAND):
    """
    collects commands valid only during NORM phase
    """

    def goto_CONF(self, to=3):
        """
        Set CONF as the next phase
        :param to: timeout
        :return: bool
        """
        return self.cmd_void_void(CYBLE_SERVICE_CMD_CHAR_HANDLE, 0xE6, to=to)

    def force_alarm(self, to=3):
        """
        force the alarm
        :param to: timeout
        :return: bool
        """
        return self.cmd_void_void(CYBLE_SERVICE_CMD_CHAR_HANDLE, 0xA0, to=to)

    def set_epoch_n(self, sse):
        """
        set the seconds since the epoch
        :param sse: seconds since the epoch
        """
        prm = struct.pack('<I', sse)
        return self.cmd_prm_void(CYBLE_SERVICE_CMD_CHAR_HANDLE, 0xB1, prm)

    def cpu_stat(self):
        """
        various cpu data (mainly for battery management)
        :return: dict
        """
        rsp = self.cmd_void_rsp(CYBLE_SERVICE_CMD_CHAR_HANDLE, 0x56, dim=20)
        if rsp is not None:
            giorni, secondi, reset, pon, gupo = struct.unpack('<5I', rsp)
            return {
                'giorni': giorni,
                'secondi': secondi,
                'reset': reset,
                'pon': pon,
                'gupo': gupo
            }

        return None


class GHOST_CONF(GHOST_COMMAND):
    """
    collects commands valid only during CONF phase
    """

    def enable_not_ind(self):
        """
        enables notifications and indications
        :return: bool
        """
        return self.enable_notify_indicate(
            CYBLE_CONFIG_CMD_CLIENT_CHARACTERISTIC_CONFIGURATION_DESC_HANDLE)

    def read_times(self, to=3):
        """
        send the command to read Tnp, Tp, Tall
        :param to: timeout
        :return: tuple or None
        """
        rsp = self.cmd_void_rsp(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x8C, dim=6, to=to)
        if rsp is not None:
            return struct.unpack('<3H', rsp)

        return None

    def write_times(self, Tnp, Tp, Tall, to=3):
        """
        send the command to write Tnp, Tp, Tall
        :param Tnp: see doc
        :param Tp: see doc
        :param Tall: see doc
        :param to: timeout
        :return: bool
        """
        prm = struct.pack('<3H', Tnp, Tp, Tall)
        return self.cmd_prm_void(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x1A, prm, to=to)

    def goto_NORM(self, to=3):
        """
        Set NORM as the next phase
        :param to: timeout
        :return: bool
        """
        return self.cmd_void_void(CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xC0, to=to)

    def goto_PROD(self, to=3):
        """
        Set PROD as the next phase
        :param to: timeout
        :return: bool
        """
        return self.cmd_void_void(CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xD2, to=to)

    def exit_MAGA(self, to=3):
        """
        Set CONF as the next phase
        :param to: timeout
        :return: bool
        """
        return self.cmd_void_void(CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x91, to=to)

    def read_ver(self, to=3):
        """
        send the command to read the version
        :param to: timeout
        :return: string or None
        """
        rsp = self.cmd_void_rsp(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x57, dim=4, to=to)
        if rsp is not None:
            glob = struct.unpack('<I', rsp)[0]
            mino = glob & 0x00FFFFFF
            magg = glob >> 24

            sver = ''
            if magg & (1 << 7):
                magg = magg & ~(1 << 7)
                sver = 'dbg '

            return sver + '{}.{}'.format(magg, mino)

        return None

    # def read_tel(self, to=3):
    #     """
    #     send the command to read the phone number that will receive the alarm sms
    #     :param to: timeout
    #     :return: string
    #     """
    #     rsp = self.cmd_void_rsp(
    #         CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xF3, to=to)
    #     if rsp is not None:
    #         return rsp.decode('ascii')
    #
    #     return None

    # def write_tel(self, tel, to=3):
    #     """
    #     send the command to write the phone number that will receive the alarm sms
    #     :param tel: string
    #     :param to: timeout
    #     :return: bool
    #     """
    #     if tel is None:
    #         return self.cmd_void_void(
    #             CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x32, to=to)
    #
    #     prm = tel.encode('ascii')
    #     return self.cmd_prm_void(
    #         CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x32, prm, to=to)

    # def read_fsms(self, to=3):
    #     """
    #     send the command to read the sms format string
    #     :param to: timeout
    #     :return: string
    #     """
    #     rsp = self.cmd_void_rsp(
    #         CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xEB, to=to)
    #     if rsp is not None:
    #         return rsp.decode('ascii')
    #
    #     return None

    # def write_fsms(self, sms_fs, to=3):
    #     """
    #     send the command to write the sms format string
    #     :param sms_fs: string
    #     :param to: timeout
    #     :return: bool
    #     """
    #     if sms_fs is None:
    #         return self.cmd_void_void(
    #             CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x78, to=to)
    #
    #     prm = sms_fs.encode('ascii')
    #     return self.cmd_prm_void(
    #         CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x78, prm, to=to)

    def read_broker(self, to=3):
        """
        send the command to read the broker's data
        :param to: timeout
        :return: dict
        """
        rsp = self.cmd_void_rsp(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x96, to=to)
        if rsp is not None:
            broker = {}
            if len(rsp) > 2:
                porta = struct.unpack('<H', rsp[:2])
                indi = rsp[2:]

                broker['port'] = porta[0]
                broker['address'] = indi.decode('ascii')
            return broker

        return None

    def write_broker(self, addr, port, to=3):
        """
        send the command to update the broker's data
        :param addr: string or None
        :param port: int
        :param to: timeout
        :return: bool
        """
        if addr is None:
            return self.cmd_void_void(
                CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x63, to=to)

        prm = struct.pack('<H', port & 0xFFFF)
        prm += addr.encode('ascii')
        return self.cmd_prm_void(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x63, prm, to=to)

    def ctrl_agg(self, iniz, to=3):
        """
        starts/stops update (that is, the bootloader profile)
        :param iniz: True -> start
        :param to: timeout
        :return: bool
        """
        ca = 0xD0487F27 if iniz else 0x74F27D60

        prm = struct.pack('<I', ca)
        return self.cmd_prm_void(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xA5, prm, to=to)

    def set_epoch_c(self, sse, to=3):
        """
        set the seconds since the epoch
        :param sse: seconds since the epoch
        :return: bool
        """
        prm = struct.pack('<I', sse)
        return self.cmd_prm_void(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0xB1, prm, to=to)

    def read_epoch(self, to=3):
        """
        read device epoch
        :param to: timeout
        :return: epoc or None
        """
        rsp = self.cmd_void_rsp(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x2A, to=to, dim=4)
        if rsp is not None:
            return struct.unpack('<I', rsp)[0]

        return None

    def write_all_tmd(self, gprs, ritenta, intervallo, slip=0, to=3):
        """
        write the parameters for tmd style alarms
        :param gprs: timeout for network activation (seconds)
        :param ritenta: sms retries
        :param intervallo: timeout after sms failure (seconds)
        :param slip: sleep period
        :return: bool
        """
        prm = struct.pack('<HB2H', gprs, ritenta, intervallo, slip)
        return self.cmd_prm_void(
            CYBLE_CONFIG_CMD_CHAR_HANDLE, 0x14, prm, to=to)

    def read_all_tmd(self, to=3):
        """
        read the parameters for tmd style alarms
        :param to: timeout
        :return: dict or None
        """
        rsp = self.cmd_void_rsp(
            CYBLE_CONFIG_CMD_CHAR_HANDLE,
            0x3C,
            dim=2 + 1 + 2 + 2,
            to=to)
        if rsp is not None:
            gprs, ritenta, intervallo, slip = struct.unpack('<HB2H', rsp)
            return {
                'gprs': gprs,
                'ritenta': ritenta,
                'intervallo': intervallo,
                'slip': slip
            }

        return None


class GHOST(CY567x.CY567x, GHOST_CONF, GHOST_NORM, bl.CY_BL_SERVICE):
    """
    Uses CY567x to implement ghost's interfaces
    """

    # cfr cyBle_gattDB, riga 0x2A05u (Service Changed)
    CYBLE_SERVICE_CHANGED_CLIENT_CHARACTERISTIC_CONFIGURATION_DESC_HANDLE = 0x000F
    CYBLE_SERVICE_CHANGED_CHAR_HANDLE = 0x000E

    def abil_var_servizi(self, evento):
        """
        enable service changed notification
        :param evento: threading.Event
        :return: bool
        """
        self.sincro['uvs'] = evento
        msg = struct.pack('<H', 0x0003)
        return self.write_characteristic_value(
            self.CYBLE_SERVICE_CHANGED_CLIENT_CHARACTERISTIC_CONFIGURATION_DESC_HANDLE, msg)

    def _reset(self, coda):
        tq = self.sincro['rsp']
        if coda == 'SCAN':
            tq = self.sincro['scan']
        elif coda == 'BLR':
            tq = self.sincro['blr']

        while not tq.empty():
            try:
                tq.get_nowait()
                # tq.task_done()
            except queue.Empty:
                break

    def __init__(self, porta=None, logga=False):
        # prima di sincro!
        bl.CY_BL_SERVICE.__init__(self)

        self.sincro = {
            # cypress bootloader service
            'blr': queue.Queue(),
            # list of devices
            'scan': queue.Queue(),
            # user list of devices
            'user': None,
            # signaled by gap_auth_req_cb
            'authReq': threading.Event(),
            # signaled by gap_passkey_entry_request_cb
            'pairReq': threading.Event(),
            # command response
            'rsp': queue.Queue()
        }

        self.priv = None

        self.crc = crcmod.Crc(0x11021, 0xC681, False, 0x0000)

        self.srvdata = None

        CY567x.CY567x.__init__(self, porta=porta)

        self.mio = None

        self.disc = None

        if logga:
            self.logger = utili.LOGGA('ghost')
        else:
            self.logger = utili.LOGGA()

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
            self.logger.debug('io sono ' + utili.str_da_mac(mio))
        except utili.Problema as err:
            self.logger.critical(str(err))

    def reiniz(self):
        """
        reinit cy5677 dongle
        :return: bool
        """
        try:
            self.disconnect()

            if not self.init_ble_stack():
                raise utili.Problema('err init')

            if not self.set_device_io_capabilities('KEYBOARD DISPLAY'):
                raise utili.Problema('err capa')

            if not self.set_local_device_security('3'):
                raise utili.Problema('err security')

            return True
        except utili.Problema as err:
            print(err)
            return False

    def set_disc(self, func):
        """
        set the callback that will be called when disconnection occurs
        :param func:
        :return:
        """
        self.disc = func

    def start_find(self, coda):
        """
        find all the ghosts around you
        :param coda: the queue that will receive ghost's info
        :return: bool
        """
        if self.sincro['user'] is None:
            self.srvdata = None
            self.sincro['user'] = coda
            if not self.scan_start():
                self.sincro['user'] = None

            return self.sincro['user'] is not None

        return False

    def stop_find(self):
        """
        stops the generic scan
        :return: bool
        """
        if self.sincro['user'] is not None:
            if self.scan_stop():
                self.sincro['user'] = None
                return True
            return False
        return True

    def find(self, cp, to=10):
        """
        find the ghost with a specific serial number
        :param cp: serial number (i.e. 'XXXAT000000')
        :param to: timeout
        :return: dict (cfr scan_report) or None
        """

        sdata = service_data_from(cp)
        self.logger.info('find <' + cp + '> => ' + utili.esa_da_ba(sdata, ' '))

        self.srvdata = sdata

        # empty scan queue
        self._reset('SCAN')

        # find it
        if self.scan_start():
            try:
                ud = self.sincro['scan'].get(True, to)
                self.scan_stop()
                return ud
            except queue.Empty:
                self.scan_stop()

        return None

    def _compute_passkey(self, bda, secret):
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

    def connect_to(self, bda, mode, secret, to=20):
        """
        execute connection with authentication and authorization
        :param bda: mac address (bytearray)
        :param mode: 'CONF' o 'NORM'
        :param secret: bytearray
        :param to: timeout
        :return: bool
        """
        self.logger.info('connect_to')

        pk = self._compute_passkey(bda, secret)
        self.logger.debug('passkey={:06d}'.format(pk))

        self.sincro['authReq'].clear()
        self.sincro['pairReq'].clear()

        try:
            # connection
            if not self.connect(bda, public=False):
                raise utili.Problema("err connect")

            # authentication
            if not self.sincro['authReq'].wait(to):
                raise utili.Problema("err autReq")

            mtu = self.exchange_gatt_mtu_size()
            if mtu == 0:
                raise utili.Problema('err mtu')
            print('mtu {}'.format(mtu))

            if not self.initiate_pairing_request():
                raise utili.Problema('err pair req')

            if not self.sincro['pairReq'].wait(to):
                raise utili.Problema("err pairReq")

            if not self.pairing_passkey(pk):
                raise utili.Problema('err passkey')

            # la cy5677 non funziona benissimo
            time.sleep(2)

            # authorization
            crt_ = CYBLE_SERVICE_AUTHOR_CHAR_HANDLE
            if mode == 'CONF':
                crt_ = CYBLE_CONFIG_AUTHOR_CHAR_HANDLE
            if not self._authorize(crt_):
                raise utili.Problema('err autor')

            return True

        except utili.Problema as err:
            self.logger.error(str(err))
            return False

    def _authorize(self, car):
        """
        execute the challenge/response procedure
        :return: bool
        """
        chl = self.read_characteristic_value(car)
        if chl is None:
            self.logger.error("_authorize.read_characteristic_value")
            return False

        challenge = self.priv.decrypt(chl)
        if challenge is None:
            self.logger.error("_authorize.decrypt")
            return False

        pt = bytearray(self.mio)
        bc = challenge[6:]
        for _elem in bc:
            _elem = (~_elem) & 0xFF
            pt.append(_elem)
        response = self.priv.crypt(pt)

        return self.write_characteristic_value(car, response)

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

    def _send_cmd_and_rx_rsp(self, char, msg, to, cmd):
        try:
            if not self.write_characteristic_value(char, msg):
                raise utili.Problema('? write_characteristic_value ?')

            _crt, ntf = self.sincro['rsp'].get(True, to)
            if _crt != char:
                raise utili.Problema('? crt ?')

            rsp = self._extract_response(ntf)
            if rsp is None:
                raise utili.Problema('? rsp ?')

            if rsp['cmd'] != cmd:
                raise utili.Problema('? cmd ?')

            return rsp

        except (queue.Empty, utili.Problema) as err:
            if isinstance(err, utili.Problema):
                print(err)
            return None

    def cmd_void_void(self, char, cmd, to=3):
        msg = self._create_command(cmd)

        rsp = self._send_cmd_and_rx_rsp(char, msg, to, cmd)
        return rsp is not None

    def cmd_void_rsp(self, char, cmd, dim=None, to=3):
        msg = self._create_command(cmd)

        try:
            rsp = self._send_cmd_and_rx_rsp(char, msg, to, cmd)

            if rsp is None:
                raise utili.Problema('? error ?')

            if dim is not None:
                if dim != len(rsp['prm']):
                    raise utili.Problema('? prm ?')

            return rsp['prm']

        except (queue.Empty, utili.Problema) as err:
            if isinstance(err, utili.Problema):
                print(err)
            return None

    def cmd_prm_void(self, char, cmd, prm, to=3):
        msg = self._create_command(cmd, prm=prm)

        rsp = self._send_cmd_and_rx_rsp(char, msg, to, cmd)
        return rsp is not None

    def enable_notify_indicate(self, char):
        msg = struct.pack('<H', 0x0003)
        return self.write_characteristic_value(char, msg)

    def _find_all_ghosts(self, _sd, un_sr):
        un_sr['prod'] = nsp_from(_sd)
        self.logger.info('trovato ' + str(un_sr))
        self.sincro['user'].put_nowait(un_sr)

    def scan_progress_cb(self, adv: bytearray):
        sr = scan_util.scan_report(adv)
        self.logger.debug(str(sr))
        if sr['adv_type'] != 'Connectable undirected advertising':
            return

        adv = scan_util.scan_advertise(sr['data'])
        self.logger.debug(str(adv))
        for _elem in adv:
            if _elem[0] != 'srvd128':
                continue

            if _elem[1] in (srv_norm, srv_conf):
                self.logger.info(str(adv))
                sr['fase'] = 'NORM' if _elem[1] == srv_norm else 'CONF'
                if self.srvdata is None:
                    self._find_all_ghosts(_elem[2], sr)
                else:
                    # find a ghost
                    srvdata = _elem[2]
                    if srvdata == self.srvdata:
                        print(sr['bda'] + ' {} dB '.format(sr['rssi']))
                        self.sincro['scan'].put_nowait(sr)

    def gap_auth_req_cb(self, ai):
        self.sincro['authReq'].set()

    def gap_passkey_entry_request_cb(self):
        self.sincro['pairReq'].set()

    def gattc_handle_value_ntf_cb(self, crt, ntf):
        print('ntf crt={:04X}'.format(crt))

        if self.blc is None:
            self.sincro['rsp'].put_nowait((crt, ntf))
        elif crt != self.blc:
            self.sincro['rsp'].put_nowait((crt, ntf))
        else:
            self.sincro['blr'].put_nowait(ntf)

    def gattc_handle_value_ind_cb(self, crt, result, ind):
        print('ind crt={:04X}'.format(crt))
        if crt == self.CYBLE_SERVICE_CHANGED_CHAR_HANDLE:
            # rileggere i servizi
            self.sincro['uvs'].set()

    def gap_device_disconnected_cb(self, reason):
        if self.disc is not None:
            self.disc(reason)


DESCRIZIONE = \
    '''
    prova della demo
    '''

if __name__ == '__main__':

    import argparse

    FAKE_PRD = 'TD3py239168'

    sd = service_data_from(FAKE_PRD)
    print(utili.esa_da_ba(sd, ' '))
    nsp = nsp_from(sd)
    print(nsp)
    print(FAKE_PRD == nsp)

    FAKE_SECRET = bytes([
        0x1D, 0x2B, 0xE0, 0x8B, 0xF0, 0x37, 0x1C, 0x60,
        0x8B, 0xC3, 0xC7, 0x5A, 0x66, 0x6D, 0x89, 0x66,
        0xA2, 0x43, 0x4D, 0x5F, 0x60, 0xA6, 0xCA, 0x91,
        0xDF, 0x3B, 0x10, 0x22, 0x84, 0xBD, 0x72, 0x1F,
        0x06, 0xA2, 0x30, 0xD2, 0xD4, 0x5C, 0xAB, 0x57,
        0x98, 0x8A, 0x92, 0xC2, 0x02, 0x86, 0x13, 0xAB,
        0x23, 0xC7, 0x1A, 0x98, 0xBE, 0x0B, 0x8D, 0x25,
        0x12, 0xB3, 0x59, 0xBF, 0x95, 0xAF, 0x5D, 0xF5
    ])

    # argomenti
    argom = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=DESCRIZIONE)
    # argom.add_argument('mac', help="L'indirizzo del dispositivo (xx:yy:..ww)")
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

    # MAC = arghi.mac
    MTU = arghi.mtu
    # DIM = arghi.dim
    # NUM = arghi.num
    # criterio = lambda cnt, lim: True
    # if NUM:
    #     criterio = lambda cnt, lim: cnt < lim

    # test
    ghost = GHOST()

    if ghost.is_ok():
        try:
            elem = ghost.find(FAKE_PRD)
            if elem is None:
                raise utili.Problema('no disp')

            MAC = elem['bda']
            MODE = elem['fase']

            if not ghost.connect_to(MAC, MODE, FAKE_SECRET):
                raise utili.Problema('err connect')
            print('connesso')

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

                # ntel = ghost.read_tel()
                # if ntel is None:
                #     raise utili.Problema('err read_tel')
                # print('ntel=<' + ntel + '>')

                # fsms = ghost.read_fsms()
                # if fsms is None:
                #     raise utili.Problema('err read_fsms')
                # print('fsms=<' + fsms + '>')

                # if not ghost.write_fsms('data=%d, ora=%h, lat=%a, lon=%o'):
                #     raise utili.Problema('err write_fsms')
                # print('nuovo fsms')

                if not ghost.goto_NORM():
                    raise utili.Problema('err goto_NORM')
                print('goto_NORM OK')
            else:
                if not ghost.set_epoch_n(utili.seconds_since_the_epoch()):
                    raise utili.Problema('err set_epoch')
                print('set_epoch OK')

                # if not ghost.goto_CONF():
                #     raise utili.Problema('err goto_CONF')
                # print('goto_CONF OK')

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        ghost.disconnect()
        ghost.close()
