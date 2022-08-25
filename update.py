"""
update a device with cypres's bootloader profile
"""

import queue
import struct

import CY567x
import scan_util
import cyacd
import utili


class EXAMPLE(CY567x.CY567x):
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

    def __init__(self, porta=None):
        self.sincro = {
            # list of devices
            'scan': queue.Queue(),
            # bootloader response
            'blr': queue.Queue()
        }

        self.mac = None

        self.blc = None

        CY567x.CY567x.__init__(self, porta=porta)

        try:
            if not self.is_ok():
                raise utili.Problema('not OK')

            if not self.init_ble_stack():
                raise utili.Problema('err init')

            if not self.set_device_io_capabilities('KEYBOARD DISPLAY'):
                raise utili.Problema('err capa')

            if not self.set_local_device_security('2'):
                raise utili.Problema('err security')

            mio = self.my_address()
            if mio is None:
                raise utili.Problema('err bdaddr')

            self.mio = mio
            print('io sono ' + utili.stringa_da_mac(mio))
        except utili.Problema as err:
            print(err)

    def _reset(self, coda):
        tq = self.sincro['scan']
        if coda == 'BLR':
            tq = self.sincro['blr']

        while not tq.empty():
            try:
                tq.get_nowait()
            except queue.Empty:
                break

    def find(self, bdadd, to=5):
        """
        find the device
        :param bdadd: mac address string
        :param to: timeout
        :return: bool
        """

        # empty scan queue
        self._reset('SCAN')

        self.mac = bdadd

        # find it
        if self.scan_start():
            try:
                _ = self.sincro['scan'].get(True, to)
                self.scan_stop()
                return True
            except queue.Empty:
                self.scan_stop()

        return False

    def scan_progress_cb(self, adv):
        if self.mac is not None:
            sr = scan_util.scan_report(adv)
            if sr['bda'] == self.mac:
                print(sr['bda'] + ' {} dB '.format(sr['rssi']))
                self.sincro['scan'].put_nowait(sr)
                self.mac = None

    def gattc_handle_value_ntf_cb(self, crt, ntf):
        if self.blc is None:
            return

        if crt != self.blc:
            return

        self.sincro['blr'].put_nowait(ntf)

    def _bl_csum(self, pckh):
        csum = 0
        for elem in pckh:
            csum += elem
        csum = (~csum) & 0xFFFF
        csum += 1

        return csum & 0xFFFF

    def _bl_pkt_trail(self, pkt):
        return struct.pack('<HB', self._bl_csum(pkt), self.EOP)

    def _bl_get_msg(self, pkt):
        if len(pkt) < 7:
            return None
        if pkt[0] != self.SOP:
            return None
        if pkt[-1] != self.EOP:
            return None
        csump = struct.unpack('<H', pkt[-3:-1])[0]
        csumc = self._bl_csum(pkt[:-3])
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
        if self.write_characteristic_value(self.blc, msg):
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
        if self.write_characteristic_value(self.blc, msg):
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

    def bl_data(self, data, dim=137, to=10):
        """
        Queue up a block of data for programming
        :param data: bytearray
        :param dim: to send
        :param to: timeout
        :return: bool
        """
        if self.blc is None:
            return False

        msg = struct.pack('<BBH', self.SOP, self.COMMAND_DATA, dim)
        msg += data[:dim]
        msg += self._bl_pkt_trail(msg)

        self._reset('BLR')
        if self.write_long_characteristic_value(self.blc, msg):
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

    def bl_program(self, aid, rown, data=None, to=10):
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
        if self.write_long_characteristic_value(self.blc, msg):
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
        if self.write_long_characteristic_value(self.blc, msg):
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
        if self.write_characteristic_value(self.blc, msg):
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


if __name__ == '__main__':
    #mac = "00:A0:50:C4:A4:2D"
    mac = "00:A0:50:D4:19:AB"
    nomef = 'BLE_External_Memory_Bootloadable01.cyacd'

    # Cypress Bootloader Service: 2.1 Bootloader Service Definition
    bl_service = '00060000-F8CE-11E4-ABF4-0002A5D5C51B'

    dispo = EXAMPLE(porta='com22')

    try:
        if not dispo.is_ok():
            raise utili.Problema('no dongle')

        cyacd = cyacd.CYACD()
        cyacd.load(nomef)

        if not dispo.find(mac):
            raise utili.Problema('not found')

        if not dispo.connect(mac):
            raise utili.Problema('not connected')

        # alcune caratteristiche sono cifrate
        if not dispo.initiate_pairing_request():
            raise utili.Problema('no pairing')

        # Log di CySmart
        ps = dispo.find_primary_service(bl_service)
        if ps is None:
            raise utili.Problema('no service')
        ps['uuid128'] = bl_service
        print(ps)

        lc = dispo.discover_all_characteristics(ps)
        if lc is None:
            raise utili.Problema('no characteristic')
        print(lc)
        if len(lc) == 1:
            lc = lc[0]
        else:
            raise utili.Problema('too much characteristic')
        print(lc)

        ccch = lc['value'] + 1
        cd = dispo.discover_characteristic_descriptors(ccch)
        if cd is None:
            raise utili.Problema('no characteristic descriptor')
        print(cd)
        if len(cd) == 1:
            cd = cd[0]
        else:
            raise utili.Problema('too much characteristic descriptor')
        print(cd)

        if 'uuid16' not in cd:
            raise utili.Problema('no uuid16 descriptor')

        if cd['uuid16'] != 0x2902:
            raise utili.Problema('no client characteristic configuration')

        if not dispo.write_characteristic_descriptor(cd['attr'], ntf=True):
            raise utili.Problema('err abil notif')

        risp = dispo.read_characteristic_descriptor(cd['attr'])
        if risp is None:
            raise utili.Problema('err stato notif')
        if risp[0]:
            print('notifiche abilitate')
        else:
            raise utili.Problema('err notifiche disabilitate')

        # adesso si balla!
        cdd = dispo.bl_enter(lc)
        if cdd is None:
            raise utili.Problema('err start bl')
        print('SiliconId={:08X}'.format(cdd['SiliconId']))
        print('Revision={}'.format(cdd['Revision']))
        print('Version=' + cdd['Version'])

        if cdd['SiliconId'] != cyacd.sil_id:
            raise utili.Problema('err siliconid diversi')
        if cdd['Revision'] != cyacd.sil_rev:
            raise utili.Problema('err revision diversi')

        fs = dispo.bl_flash_size()
        if fs is None:
            raise utili.Problema('err flash size')
        print(fs)

        for riga in cyacd.rows:
            print(riga)

            dati = riga['row']
            if not dispo.bl_data(dati):
                raise utili.Problema('err invio dati')

            resto = dati[dispo.DIM:]
            if len(resto) == 0:
                resto = None
            if not dispo.bl_program(riga['arrayId'], riga['rowNum'], resto):
                raise utili.Problema('err programmazione')

            rcs = dispo.bl_verify(riga['arrayId'], riga['rowNum'])
            if rcs is None:
                raise utili.Problema('err verifica')
            if rcs != riga['checksum']:
                raise utili.Problema(
                    'err checksum diversi remoto={} != cyacd={}'.format(
                        rcs, riga['checksum']))

        if not dispo.bl_validate():
            raise utili.Problema('err bootloadable non valido')

        if not dispo.bl_exit():
            raise utili.Problema('err exit')

        print('fine')

    except utili.Problema as err:
        print(err)

    dispo.close()
