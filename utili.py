#!/usr/bin/env python

"""
    Varie
"""

from __future__ import print_function

import logging
import threading
import random
import string
import time


def validaStringa(x, dimmin=None, dimmax=None):
    """
        Usata sui campi testo per validare che la
        lunghezza sia fra un minimo e un massimo
    """
    esito = False

    if x is None:
        pass
    elif dimmin is None:
        if dimmax is None:
            # Accetto qls dimensione
            esito = True
        elif len(x) > dimmax:
            pass
        else:
            esito = True
    elif len(x) < dimmin:
        pass
    elif dimmax is None:
        esito = True
    elif len(x) > dimmax:
        pass
    else:
        esito = True

    return esito


def validaCampo(x, mini=None, maxi=None):
    """
        Se la stringa x e' un intero, controlla
        che sia tra i due estremi inclusi
    """
    esito = False
    val = None
    while True:
        if x is None:
            break

        if any(x) == 0:
            break

        try:
            val = int(x)
        except ValueError:
            try:
                val = int(x, 16)
            except ValueError:
                pass

        if val is None:
            break

        # Entro i limiti?
        if mini is None:
            pass
        elif val < mini:
            break
        else:
            pass

        if maxi is None:
            pass
        elif val > maxi:
            break
        else:
            pass

        esito = True
        break

    return esito, val


def strVer(vn):
    """
        Converte la versione del fw in stringa
    """

    vmag = vn >> 24
    vmin = vn & 0xFFFFFF

    ver = str(vmag)
    ver += "."
    ver += str(vmin)

    return ver


def verStr(vs):
    """
        Converte una stringa x.y nella versione del fw
    """
    magg, dummy, mino = vs.partition('.')

    esito, ver = validaCampo(magg, 0, 255)

    if not esito:
        return False, 0

    esito, v2 = validaCampo(mino, 0, 0xFFFFFF)
    if not esito:
        return False, 0

    ver <<= 24
    ver += v2

    return True, ver


def intEsa(val, cifre=8):
    """
        Converte un valore in stringa esadecimale senza 0x iniziale
    """
    x = hex(val)
    s = x[2:]
    ver = ""
    dim = len(s)
    while dim < cifre:
        ver += "0"
        dim += 1

    ver += s.upper()

    return ver


def StampaEsa(cosa, titolo=''):
    """
        Stampa un dato binario
    """
    if cosa is None:
        print('<vuoto>')
    else:
        #print(titolo, binascii.hexlify(cosa))
        print(titolo + ''.join('{:02X} '.format(x) for x in cosa))


def gomsm(conv, div):
    """
        Converte un tempo in millisecondi in una stringa
    """
    if conv[-1] < div[0]:
        return conv

    resto = conv[-1] % div[0]
    qznt = conv[-1] // div[0]

    conv = conv[:len(conv) - 1]
    conv = conv + (resto, qznt)

    div = div[1:]

    if any(div):
        return gomsm(conv, div)

    return conv


def stampaDurata(milli):
    """
        Converte un numero di millisecondi in una stringa
        (giorni, ore, minuti, secondi millisecondi)
    """
    x = gomsm((milli,), (1000, 60, 60, 24))
    unita = ('ms', 's', 'm', 'o', 'g')

    durata = ""
    for i, elem in enumerate(x):
        if any(durata):
            durata = ' ' + durata
        durata = str(int(elem)) + unita[i] + durata
    return durata


def baMac(mac):
    """
        Converte da mac a bytearray
    """
    componenti = mac.split(':')
    if len(componenti) != 6:
        return None

    mac = bytearray()
    for elem in componenti:
        esito, val = validaCampo('0x' + elem, 0, 255)
        if esito:
            mac += bytearray([val])
        else:
            mac = None
            break

    return mac


class Problema(Exception):
    """
        Eccezione
    """

    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

    def __str__(self):
        return self.msg


class Periodico(threading.Thread):
    """
        Crea un timer periodico
    """

    def __init__(self, funzione, param=None):
        threading.Thread.__init__(self)

        self.secondi = None
        self.funzione = funzione
        self.param = param

        self.evento = threading.Event()

    def run(self):
        while True:
            esci = self.evento.wait(self.secondi)
            if esci:
                break

            if self.param is not None:
                self.funzione(self.param)
            else:
                self.funzione()

    def avvia(self, secondi):
        """
            fa partire il timer
        :param secondi: indovina
        :return: niente
        """
        if self.secondi is None:
            self.secondi = secondi
            self.start()

    def termina(self):
        """
            ferma il timer
        :return: niente
        """
        if self.secondi is not None:
            self.evento.set()
            self.join()
            self.secondi = None

    def attivo(self):
        """
            vera se il timer sta girando
        :return: bool
        """
        return self.secondi is not None


def stampaTabulare(pos, dati, prec=4):
    """
        Stampa il bytearray dati incolonnando per 16
        prec e' il numero di cifre di pos
    """
    testa_riga = '%0' + str(prec) + 'X '

    print('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F'.rjust(prec + (3 * 16)))
    primo = pos & 0xFFFFFFF0

    bianchi = pos & 0x0000000F
    riga = testa_riga % primo
    while bianchi:
        riga += '   '
        bianchi -= 1

    conta = pos & 0x0000000F
    for x in dati:
        riga += '%02X ' % (x)
        conta += 1
        if conta == 16:
            print(riga)
            primo += 16
            riga = testa_riga % primo
            conta = 0
    if conta:
        print(riga)


def byte_casuali(quanti):
    """
    indovina
    :param quanti: numero di elementi
    :return: bytearray
    """
    vc = bytearray()
    for _ in range(quanti):
        x = random.randint(0, 255)
        vc.append(x)
    return vc

def ba_da_esa(esa, sep='-'):
    """
    Converte una stringa esadecimale di tipo xx-yy-zz
    nel bytearray [xx, yy, zz]
    :param esa: stringa di byte esadecimali, p.e. 'AB-CD'
    :param sep: separatore
    :return: il bytearray, p.e. [0xAB 0xCD]
    """
    ba = bytearray()
    x = esa.split(sep)
    try:
        for y in x:
            ba.append(int(y, base=16))
    except ValueError:
        ba = None

    return ba

def esa_da_ba(ba, sep='-'):
    """
    Converte un bytearray [xx, yy, zz] in
    stringa esadecimale "xx-yy-zz"
    :param ba: bytearray
    :param sep: separatore
    :return:
    """
    esa = ''
    if len(ba) == 0:
        pass
    elif len(ba) == 1:
        esa += '%02X' % ba[0]
    else:
        for i in range(len(ba) - 1):
            esa += '%02X' % ba[i]
            esa += sep
        esa += '%02X' % ba[len(ba) - 1]

    return esa

def str_da_mac(cam):
    """
    Converte un mac (bytearray [xx, .. zz]) in
    stringa "zz:..:xx"
    :param cam: bytearray
    :return: stringa
    """
    if len(cam) != 6:
        return '???'

    mac = bytearray(_ for _ in reversed(cam))

    esa = ''
    for i in mac:
        esa += '%02X' % i
        esa += ':'

    return esa[:len(esa) - 1]

def mac_da_str(stri):
    """
    Converte un mac (stringa 'xx:..:zz') in
    mac (bytearray [zz, ..., xx])
    :param stri: bdaddr
    :return: stringa
    """
    cam = bytearray()
    x = stri.split(':')
    if len(x) != 6:
        return None

    try:
        for y in x:
            cam.append(int(y, base=16))
        mac = bytearray(_ for _ in reversed(cam))
        return mac
    except ValueError:
        return None

def _cod_finto(dim):
    base = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    cod = ''
    while dim > 0:
        random.shuffle(base)
        dimp = min(dim, len(base))
        cod = cod + ''.join(base[:dimp])
        dim -= dimp

    return cod


def cod_prod(pre):
    """
    Crea un finto codice prodotto
    :param pre: prefisso (dipende dal prodotto)
    :return: una stringa
    """
    return pre + 'py' + _cod_finto(6)


def cod_scheda():
    """
    Crea un finto codice scheda
    :return:
    """
    return _cod_finto(12)


def stringa_casuale(dim):
    """
    Restituisce una stringa alfanumerica casuale
    :param dim: numero di caratteri da generare
    :return: stringa
    """
    base = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choice(base) for _ in range(dim))

class CRONOMETRO():
    def __init__(self):
        self.inizio = 0
        # if sys.platform.startswith("win32"):
        #     self.tempo = time.clock
        # else:
        #     self.tempo = time.time
        self.tempo = time.time

    def conta(self):
        self.inizio = self.tempo()

    def durata(self):
        return self.tempo() - self.inizio

class LOGGA:

    def __init__(self, logger=None):
        if logger is None:
            self.logger = None
        else:
            self.logger = logging.getLogger(logger)

    def debug(self, msg):
        if self.logger is not None:
            self.logger.debug(msg)

    def info(self, msg):
        if self.logger is not None:
            self.logger.info(msg)

    def warning(self, msg):
        if self.logger is not None:
            self.logger.warning(msg)

    def error(self, msg):
        if self.logger is not None:
            self.logger.error(msg)

    def critical(self, msg):
        if self.logger is not None:
            self.logger.critical(msg)

def girino(x):
    _girino = ['-', '\\', '|', '/', '*']
    if x % 1000 == 0:
        print('\b.')
    elif x % 10 == 0:
        print('\b. ', end='', flush=True)
    else:
        print('\b' + _girino[x % len(_girino)], end='', flush=True)


if __name__ == '__main__':
    for z in range(23):
        girino(z+1)
        time.sleep(.1)
    # MILLISEC = 123456789.34
    # print(gomsm((MILLISEC,), (1000, 60, 60, 24)))
    # print(stampaDurata(MILLISEC))
