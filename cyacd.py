"""
cfr inst-dir/Cypress/PSoC Creator/version/PSoC Creator/cybootloaderutils
"""

import string
import struct


def _convert(char):
    if char in string.digits:
        return ord(char) - ord('0')
    char = char.upper()
    if char in string.hexdigits:
        return ord(char) - ord('A') + 10
    return 0


def _bytes_from_char(a_row):
    a_row = a_row.strip('\n')

    res = bytearray()
    while len(a_row) >= 2:
        msb = _convert(a_row[0])
        lsb = _convert(a_row[1])
        val = (msb << 4) + lsb
        res.append(val)
        a_row = a_row[2:]
    return res


class CYACD:
    def __init__(self):
        # CYDEV_CHIP_JTAG_ID
        self.sil_id = None

        self.sil_rev = None
        self.cks_type = None

        self.rows = []

        self.nf = None

    def _CyBtldr_ParseHeader(self, firstrow):
        x = struct.unpack('>IBB', firstrow)
        self.sil_id = x[0]
        self.sil_rev = x[1]
        self.cks_type = x[2]
        print(
            'silicon: id {:08X} rev {:02X}'.format(
                self.sil_id,
                self.sil_rev))

    @staticmethod
    def _CyBtldr_ParseRowData(nextrow):
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

        return {
            'arrayId': arrayId,
            'rowNum': rowNum,
            'checksum': csum,
            'row': row
        }

    def load(self, filename):
        with open(filename, 'rt') as ing:
            self.nf = filename

            # first row
            ur = ing.readline()
            ba = _bytes_from_char(ur)
            self._CyBtldr_ParseHeader(ba)

            while True:
                ur = ing.readline()
                if not any(ur):
                    break

                # remove starting :
                ba = _bytes_from_char(ur[1:])

                # next row
                rd = self._CyBtldr_ParseRowData(ba)
                if not any(rd):
                    self.rows = []
                    break

                self.rows.append(rd)

    def nomefile(self):
        return self.nf


if __name__ == '__main__':
    import sys
    import utili
    import crcmod
    import random
    import hashlib
    import secrets
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import argparse
    import proto

    DESCRIZIONE = \
        '''
        Operazioni su file cyacd per ghost sa
        '''

    argom = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=DESCRIZIONE)
    argom.add_argument(
        '-t', '--tipo',
        type=int,
        default=3,
        help='tipo binario (3: sha + cif)')
    argom.add_argument(
        '-l', '--leggi',
        action="store_true",
        help='legge il file binario (False)')
    argom.add_argument('nf',
                       help="Nome del file")

    arghi = argom.parse_args()

    INIZ = 0xDE
    FINE = 0xCE
    FUGA = 0xD7

    TIPO_POS = 10
    TIPO_MSK = 0x3F

    T_SIL = 0
    T_IV = 1
    T_RIGA = 2
    T_SHA = 3

    AID_POS = 9
    AID_MSK = 0x01

    ROW_MSK = 0x1FF


    class BINARIO(proto.PROTO):
        def __init__(self):
            proto.PROTO.__init__(self, INIZ, FINE, FUGA)
            self.iv = None
            self.h = HASH()
            self.rc = None

        def pkt_cb(self, msg):
            if len(msg) < 2 + 2:
                print('ERR pochi byte: ' + utili.esa_da_ba(msg, ' '))
                return

            testa = struct.unpack('<H', msg[:2])[0]
            msg = msg[2:]

            fcrc = crcmod.Crc(0x11021, testa, False, 0x0000)
            fcrc.update(msg)
            crc = fcrc.digest()
            if crc == bytes([0, 0]):
                # elimino crc
                msg.pop(-1)
                msg.pop(-1)

                tipo = (testa >> TIPO_POS) & TIPO_MSK
                if tipo == T_SIL:
                    if len(msg) == 5:
                        sid, rev = struct.unpack('<IB', msg)
                        print('SILICON {:08X}.{:02X}'.format(sid, rev))
                    else:
                        print('ERR: sil pochi byte: ' + utili.esa_da_ba(msg, ' '))
                elif tipo == T_IV:
                    if len(msg) == 16:
                        if self.rc is None:
                            self.rc = RIGA_CIF(bytes(msg))
                            print('IV: ' + utili.esa_da_ba(msg, ' '))
                        else:
                            print('ERR: iv doppione: ' + utili.esa_da_ba(msg, ' '))
                    else:
                        print('ERR: iv pochi byte: ' + utili.esa_da_ba(msg, ' '))
                elif tipo == T_RIGA:
                    aid = (testa >> AID_POS) & AID_MSK
                    row = testa & ROW_MSK
                    if len(msg) == 256:
                        if self.rc is None:
                            # Riga in chiaro
                            self.h.riga(msg)
                            print('RIGA[{}][{}]: '.format(aid, row) + utili.esa_da_ba(msg, ' '))
                        else:
                            # Riga cifrata
                            dec = self.rc.decifra(msg)
                            self.h.riga(dec)
                            print('RIGA[{}][{}]: '.format(aid, row) + utili.esa_da_ba(dec, ' '))
                    else:
                        print('ERR: riga pochi byte: ' + utili.esa_da_ba(msg, ' '))
                elif tipo == T_SHA:
                    if len(msg) == 32:
                        print('SHA(bin): ' + utili.esa_da_ba(msg, ' '))
                        mio = self.h.riassunto()
                        print('SHA(mio): ' + utili.esa_da_ba(mio, ' '))
                        if mio == msg:
                            print('BIN valido')
                        else:
                            print('BIN NON VALIDO')
                    else:
                        print('ERR: sha pochi byte: ' + utili.esa_da_ba(msg, ' '))
                else:
                    print('ERR tipo {} testa {:04X}'.format(tipo, testa))
            else:
                print('ERR crc')

        def err_cb(self, desc):
            print(desc)
            return False


    def intestazione(tipo, aid=None, row=None):
        if aid is None:
            aid = random.randint(0, 1000)
        if row is None:
            row = random.randint(0, 1000)
        i = (tipo & TIPO_MSK) << TIPO_POS
        i += (aid & AID_MSK) << AID_POS
        i += row & 0x1FF
        return i


    def aggiungi(dst, srg):
        for elem in srg:
            if elem in (INIZ, FINE, FUGA):
                dst.append(FUGA)
                dst.append(0xFF & (~elem))
            else:
                dst.append(elem)


    class SILICON:
        def __init__(self, sid, rev):
            ba = bytearray([INIZ])

            # intestazione
            i = intestazione(T_SIL)
            aggiungi(ba, struct.pack('<H', i))

            # dati
            dati = struct.pack('<IB', sid, rev)
            aggiungi(ba, dati)

            # crc
            fcrc = crcmod.Crc(0x11021, i, False, 0x0000)
            fcrc.update(dati)
            crc = fcrc.digest()
            aggiungi(ba, (crc[0],))
            aggiungi(ba, (crc[1],))

            ba.append(FINE)

            self.dati = ba

        def elem(self):
            return self.dati


    class RIGA:
        def __init__(self, aid, row, dati):
            ba = bytearray([INIZ])

            # intestazione
            i = intestazione(T_RIGA, aid, row)
            aggiungi(ba, struct.pack('<H', i))

            # dati
            aggiungi(ba, dati)

            # crc
            fcrc = crcmod.Crc(0x11021, i, False, 0x0000)
            fcrc.update(dati)
            crc = fcrc.digest()
            aggiungi(ba, (crc[0],))
            aggiungi(ba, (crc[1],))

            ba.append(FINE)

            self.dati = ba

        def elem(self):
            return self.dati


    class HASH:
        GHOST_SA_ID = bytearray([0x1B,
                                 0xA0,
                                 0x78,
                                 0xB2,
                                 0x8B,
                                 0x9B,
                                 0xCA,
                                 0x05,
                                 0x07,
                                 0xD5,
                                 0x81,
                                 0xE7,
                                 0x17,
                                 0x1B,
                                 0xA3,
                                 0xD7])

        def __init__(self):
            self.digest = hashlib.sha256()
            self.digest.update(bytes(HASH.GHOST_SA_ID))

        def riga(self, dati):
            self.digest.update(bytes(dati))

        def elem(self):
            ba = bytearray([INIZ])

            # intestazione
            i = intestazione(T_SHA)
            aggiungi(ba, struct.pack('<H', i))

            # dati
            dati = self.digest.digest()
            aggiungi(ba, dati)

            # crc
            fcrc = crcmod.Crc(0x11021, i, False, 0x0000)
            fcrc.update(dati)
            crc = fcrc.digest()
            aggiungi(ba, (crc[0],))
            aggiungi(ba, (crc[1],))

            ba.append(FINE)

            return ba

        def riassunto(self):
            return self.digest.digest()


    class IV:
        def __init__(self):
            self.iv = bytearray(secrets.token_bytes(16))

        def dammelo(self):
            return self.iv

        def elem(self):
            ba = bytearray([INIZ])

            # intestazione
            i = intestazione(T_IV)
            aggiungi(ba, struct.pack('<H', i))

            # dati
            aggiungi(ba, self.iv)

            # crc
            fcrc = crcmod.Crc(0x11021, i, False, 0x0000)
            fcrc.update(self.iv)
            crc = fcrc.digest()
            aggiungi(ba, (crc[0],))
            aggiungi(ba, (crc[1],))

            ba.append(FINE)

            return ba


    class RIGA_CIF:
        GHOST_SA_CH = bytes([0x2F,
                             0xD0,
                             0xC2,
                             0x66,
                             0x56,
                             0x6C,
                             0x6C,
                             0x2C,
                             0x15,
                             0xAB,
                             0xAD,
                             0xAE,
                             0x41,
                             0x48,
                             0xE4,
                             0x65,
                             0xBF,
                             0xED,
                             0x3C,
                             0x7F,
                             0x4C,
                             0xEE,
                             0x8E,
                             0x98,
                             0xBE,
                             0xE1,
                             0x2B,
                             0xD7,
                             0x1F,
                             0xC6,
                             0xEF,
                             0xEE])

        def __init__(self, iv):
            self.iv = bytes(iv)[:16]

        def elem(self, aid, row, chiaro):
            ba = bytearray([INIZ])

            # intestazione
            i = intestazione(T_RIGA, aid, row)
            aggiungi(ba, struct.pack('<H', i))

            # dati
            cipher = Cipher(
                algorithms.AES(RIGA_CIF.GHOST_SA_CH),
                modes.CBC(self.iv),
                backend=default_backend())
            encryptor = cipher.encryptor()
            scuro = encryptor.update(bytes(chiaro)) + encryptor.finalize()
            self.iv = bytes(scuro)[- 16:]

            aggiungi(ba, scuro)

            # crc
            fcrc = crcmod.Crc(0x11021, i, False, 0x0000)
            fcrc.update(scuro)
            crc = fcrc.digest()
            aggiungi(ba, (crc[0],))
            aggiungi(ba, (crc[1],))

            ba.append(FINE)

            return ba

        def decifra(self, scuro):
            cipher = Cipher(
                algorithms.AES(RIGA_CIF.GHOST_SA_CH),
                modes.CBC(self.iv),
                backend=default_backend())
            decryptor = cipher.decryptor()
            chiaro = decryptor.update(scuro) + decryptor.finalize()
            self.iv = bytes(scuro)[- 16:]
            return chiaro


    def stampa(cyacd):
        # stampa a video il contenuto
        # h = [0] * 256

        for riga in cyacd.rows:
            arrayId = riga['arrayId']
            rowNum = riga['rowNum']
            # checksum = riga['checksum']
            row = riga['row']
            # for elem in row:
            #     h[elem] += 1

            print(
                'arrayId {} rowNum {} [{}] {}'.format(
                    arrayId,
                    rowNum,
                    len(row),
                    utili.esa_da_ba(row, ' ')))

        # istogramma
        # for i in range(256):
        #     print('{} = {:02X}'.format(h[i], i))


    def conversione_1(cyacd):
        # non usa SHA e non cifra le righe
        nfb = cyacd.nomefile() + ".1.bin"

        with open(nfb, 'wb') as usc:
            s = SILICON(cyacd.sil_id, cyacd.sil_rev)
            usc.write(s.elem())

            for riga in cyacd.rows:
                arrayId = riga['arrayId']
                rowNum = riga['rowNum']
                row = riga['row']

                r = RIGA(arrayId, rowNum, row)
                usc.write(r.elem())


    def conversione_2(cyacd):
        # usa sha ma non cifra le righe
        nfb = cyacd.nomefile() + ".2.bin"

        h = HASH()
        with open(nfb, 'wb') as usc:
            s = SILICON(cyacd.sil_id, cyacd.sil_rev)
            usc.write(s.elem())

            for riga in cyacd.rows:
                arrayId = riga['arrayId']
                rowNum = riga['rowNum']
                row = riga['row']

                h.riga(row)

                r = RIGA(arrayId, rowNum, row)
                usc.write(r.elem())

            usc.write(h.elem())


    def conversione_3(cyacd):
        # sha + cifra le righe
        nfb = cyacd.nomefile() + ".3.bin"

        h = HASH()
        with open(nfb, 'wb') as usc:
            s = SILICON(cyacd.sil_id, cyacd.sil_rev)
            usc.write(s.elem())

            iv = IV()
            usc.write(iv.elem())

            rc = RIGA_CIF(iv.dammelo())

            for riga in cyacd.rows:
                arrayId = riga['arrayId']
                rowNum = riga['rowNum']
                row = riga['row']

                h.riga(row)

                usc.write(rc.elem(arrayId, rowNum, row))

            usc.write(h.elem())


    FUNZ = [stampa, conversione_1, conversione_2, conversione_3]

    if arghi.leggi:
        bin = None
        with open(arghi.nf, 'rb') as ing:
            bin = ing.read()

        if bin is not None:
            fb = BINARIO()
            fb.esamina(bin)
    else:
        if arghi.tipo in (0, 1, 2, 3):
            funz = FUNZ[arghi.tipo]
            cyacd = CYACD()

            cyacd.load(arghi.nf)

            funz(cyacd)
        else:
            print('tipo sconosciuto: {}'.format(arghi.tipo))
            print('\t0: stampa')
            print('\t1: no sha, no cif')
            print('\t2: sha, no cif')
            print('\t3: sha, cif')
