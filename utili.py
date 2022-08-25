#!/usr/bin/env python

"""
    Varie
"""

import logging
import threading
import random
import string
import time
import tkinter.filedialog as dialogo
import inspect
import serial.tools.list_ports as lp


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


def validaFloat(x, mini=None, maxi=None):
    """
        Se la stringa x e' un float, controlla
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
            val = float(x)
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

    vmag = (vn >> 24) & 0xFF
    vmin = (vn >> 16) & 0xFF
    rev = vn & 0xFFFF

    return '{}.{}.{}'.format(vmag, vmin, rev)


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

        # recupero la posizione del chiamante
        fi = inspect.getframeinfo(inspect.currentframe().f_back)
        self.pos = fi.filename + ': ' + str(fi.lineno)

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


class INTERO_ATOMICO:
    def __init__(self, val=0):
        self.val = val
        self.mux = threading.Lock()

    def leggi(self):
        x = 0
        with self.mux:
            x = self.val
        return x

    def scrivi(self, cosa):
        with self.mux:
            self.val = cosa

    def inc(self):
        with self.mux:
            self.val += 1

    def dec(self):
        with self.mux:
            self.val -= 1


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


def numero_casuale(maxi, mini=0):
    return random.randint(mini, maxi)


def ba_da_stringa(stringa, sep='-', base=16):
    """
    Converte una stringa esadecimale di tipo 'xx-yy-zz'
    nel bytearray [xx, yy, zz]
    :param stringa: stringa di byte esadecimali
    :param sep: separatore
    :return: il bytearray
    """
    stringa = stringa.lstrip(' ')
    ba = bytearray()
    x = stringa.split(sep)
    try:
        for y in x:
            ba.append(int(y, base=base))
    except ValueError:
        ba = None

    return ba


def stringa_da_ba(ba, sep='-'):
    """
    Converte un bytearray [xx, yy, zz] in
    stringa esadecimale "xx-yy-zz"
    :param ba: bytearray
    :param sep: separatore
    :return: string
    """
    stringa = ''
    if len(ba) == 0:
        pass
    elif len(ba) == 1:
        stringa += '%02X' % ba[0]
    else:
        for i in range(len(ba) - 1):
            stringa += '%02X' % ba[i]
            stringa += sep
        stringa += '%02X' % ba[len(ba) - 1]

    return stringa


def stringa_da_mac(cam):
    """
    Converte un mac (bytearray [xx, .. zz]) in
    stringa "zz:..:xx"
    :param cam: bytearray
    :return: stringa
    """
    if len(cam) != 6:
        return '???'

    mac = bytearray(_ for _ in reversed(cam))

    return stringa_da_ba(mac, ':')


def mac_da_stringa(stringa):
    """
    Converte una stringa 'xx:..:zz' in
    bytearray [zz, ..., xx]
    :param stringa: string
    :return: bytearray
    """
    cam = ba_da_stringa(stringa, ':')
    if cam is None:
        return None
    if len(cam) != 6:
        return None

    return bytearray(_ for _ in reversed(cam))


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
        self.tempo = time.perf_counter

    def conta(self):
        self.inizio = self.tempo()

    def durata(self):
        return self.tempo() - self.inizio


class LOGGA:
    # Lo script principale inizializza, p.e.:
    #     logging.basicConfig(
    #         filename='pippo.txt',
    #         level=logging.DEBUG,
    #         format='%(asctime)s - %(levelname)s - %(message)s')
    #     logging.getLogger().addHandler(logging.StreamHandler())
    # Tutti istanziano questa classe e usano i suoi metodi
    #     self.diario = utili.LOGGA(__main__ if logga else None)

    def __init__(self, logger=None):
        if logger is None:
            self.logger = None
        else:
            self.logger = logging.getLogger(logger)

    def abilitato(self):
        return self.logger is not None

    # in ordine di verbosita'

    def debug(self, msg, ba=None):
        if self.logger is not None:
            if ba is not None:
                msg = msg + ' [{}]:'.format(len(ba)) + stringa_da_ba(ba, ' ')
            self.logger.debug(msg)

    def info(self, msg):
        if self.logger is not None:
            self.logger.info(msg)

    def warning(self, msg):
        if self.logger is not None:
            self.logger.warning(msg)

    def error(self, msg):
        if self.logger is not None:
            # recupero la posizione del chiamante
            fi = inspect.getframeinfo(inspect.currentframe().f_back)

            # e la appiccico in fondo
            msg = msg + ' <' + fi.filename + ': ' + str(fi.lineno) + '>'

            self.logger.error(msg)

    def critical(self, msg):
        if self.logger is not None:
            # recupero la posizione del chiamante
            fi = inspect.getframeinfo(inspect.currentframe().f_back)

            # e la appiccico in fondo
            msg = msg + ' <' + fi.filename + ': ' + str(fi.lineno) + '>'

            self.logger.critical(msg)


# p.e.: nomefile = utili.scegli_file_esistente(self.master, [('expander',
# '.cyacd')])
def scegli_file_esistente(master, filetypes):
    opzioni = {
        'parent': master,
        'filetypes': filetypes,
        'title': 'Scegli il file',
        'defaultextension': filetypes[0][1]
    }
    filename = dialogo.askopenfilename(**opzioni)

    if filename is None:
        return None

    if not any(filename):
        return None

    return filename


def girino(x):
    _girino = ['-', '\\', '|', '/', '*']
    if x % 1000 == 0:
        print('\bK')
    elif x % 10 == 0:
        print('\b. ', end='', flush=True)
    else:
        print('\b' + _girino[x % len(_girino)], end='', flush=True)


def seconds_since_the_epoch():
    return int(time.time())


def seconds_since_the_epoch_float():
    return round(time.time(), 3)


def brokendown_time(epoch):
    bdt = time.gmtime(epoch)
    return {
        'anno': bdt.tm_year,
        'mese': bdt.tm_mon,
        'giorno': bdt.tm_mday,
        'ora': bdt.tm_hour,
        'minuti': bdt.tm_min,
        'secondi': bdt.tm_sec
    }


def lista_seriali():
    diz = {}
    lista = lp.comports()
    for elem in lista:
        desc = elem.description
        if elem.device in desc:
            pos = desc.find(elem.device)
            desc = desc[:pos - 1].strip()

        if elem.vid is None:
            diz[elem.device] = (desc,)
        else:
            manuf = '?'
            if elem.manufacturer is not None:
                manuf = elem.manufacturer.strip()
            diz[elem.device] = (desc, manuf, elem.vid, elem.pid)
    return diz


def slip(secondi):
    time.sleep(secondi)


def lettera_anno(anno: int):
    # vedi https://en.wikipedia.org/wiki/Vehicle_identification_number
    LA = {
        2010: 'A',
        2011: 'B',
        2012: 'C',
        2013: 'D',
        2014: 'E',
        2015: 'F',
        2016: 'G',
        2017: 'H',
        2018: 'J',
        2019: 'K',
        2020: 'L',
        2021: 'M',
        2022: 'N',
        2023: 'P',
        2024: 'R',
        2025: 'S',
        2026: 'T',
        2027: 'V',
        2028: 'W',
        2029: 'X',
        2030: 'Y',
        2031: '1',
        2032: '2',
        2033: '3',
        2034: '4',
        2035: '5',
        2036: '6',
        2037: '7',
        2038: '8',
        2039: '9',
    }
    try:
        return LA[anno]
    except KeyError:
        return '?'


if __name__ == '__main__':
    for z in range(10):
        girino(z)
        time.sleep(.2)
    # MILLISEC = 123456789.34
    # print(gomsm((MILLISEC,), (1000, 60, 60, 24)))
    # print(stampaDurata(MILLISEC))
