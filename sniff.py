import struct
import sys

import utili
from cycost import quale_comando, quale_evento


def leggi_dati(riga):
    pos = riga.find('Data:')
    if pos == -1:
        return None

    pos += 6
    riga = riga[pos:]
    riga = riga.rstrip(' \t\r\n')

    return utili.ba_da_esa(riga, ' ')


def stampa(cosa, dove, proto_rx, proto_tx):
    if cosa[0] == 'o':
        dove.write('OPEN\n')
        return

    if cosa[0] == 'b':
        dove.write('BAUD {}\n'.format(cosa[1]))
        return

    if cosa[0] == 'c':
        dove.write('CLOSE\n')
        return

    if cosa[0] == 'w':
        dove.write(proto_tx.stampa(cosa[1]))
    else:
        dove.write(proto_rx.stampa(cosa[1]))

    dove.write('\n')


class PROTO:

    def __init__(self, nome, primo, secondo):
        self.nome = nome
        self.primo = primo
        self.secondo = secondo

        self.lista_msg = []
        self.parz = bytearray()
        self.stato = 'attesa'
        self.dim = -1

    def reiniz(self):
        self.parz = bytearray()
        self.dim = -1
        self.stato = 'attesa'

    def chi_sei(self):
        return self.nome

    def dammi_msg(self):
        if any(self.lista_msg):
            return self.lista_msg.pop(0)

        return None

    def esamina(self, questi):
        for cosa in questi:
            if cosa == self.primo:
                self.stato = 'quasi'
            elif cosa == self.secondo:
                if self.stato == 'quasi':
                    if any(self.parz):
                        self.lista_msg.append(bytearray(self.parz))
                        self.reiniz()
                    self.stato = 'msg'
                else:
                    self.parz.append(cosa)
            else:
                if self.stato == 'quasi':
                    self.parz.append(self.primo)
                    self.stato = 'attesa'
                self.parz.append(cosa)

                self.controlla()

    def controlla(self):
        pass


class PROTO_RX(PROTO):

    def __init__(self):
        PROTO.__init__(self, 'RX', 0xBD, 0xA7)

    def controlla(self):
        if self.dim < 0:
            if len(self.parz) == 4:
                tot, _ = struct.unpack('<2H', self.parz[:4])
                self.dim = tot + 2

        if self.dim == len(self.parz):
            self.lista_msg.append(bytearray(self.parz))

            self.reiniz()
        else:
            pass

    def interpreta(self, cosa):
        if len(cosa) >= 4:
            tot, msg = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]
            tot -= 2

            if tot != len(prm):
                print(self.nome +
                      ' ERR DIM {:04X}[{} != {}]: '.format(msg, tot, len(
                          prm)) + utili.esa_da_ba(prm, ' '))
            else:
                print(
                    self.nome +
                    ' {:04X}[{}]: '.format(
                        msg,
                        tot) +
                    utili.esa_da_ba(
                        prm,
                        ' '))

            return msg, tot, prm

        print(self.nome + ' ????: ' + utili.esa_da_ba(cosa, ' '))
        return 0, 0, cosa

    def stampa(self, cosa):
        risul = self.nome + ' '
        if len(cosa) >= 4:
            tot, msg = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]
            tot -= 2

            risul += quale_evento(msg) + ' '

            if tot != len(prm):
                risul += 'ERR DIM [{} != {}]: '.format(
                    tot, len(prm)) + '\n\t' + utili.esa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                    utili.esa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.esa_da_ba(cosa, ' ')

        return risul


class PROTO_TX(PROTO):

    def __init__(self):
        PROTO.__init__(self, 'TX', 0x43, 0x59)

    def controlla(self):
        if self.dim < 0:
            if len(self.parz) == 4:
                _, tot = struct.unpack('<2H', self.parz[:4])
                self.dim = tot + 4

        if self.dim == len(self.parz):
            self.lista_msg.append(bytearray(self.parz))

            self.reiniz()
        else:
            pass

    def interpreta(self, cosa):
        if len(cosa) >= 4:
            msg, tot = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]

            if tot != len(prm):
                print(self.nome +
                      ' ERR DIM {:04X}[{} != {}]: '.format(msg, tot, len(
                          prm)) + utili.esa_da_ba(prm, ' '))
            else:
                print(
                    self.nome +
                    ' {:04X}[{}]: '.format(
                        msg,
                        tot) +
                    utili.esa_da_ba(
                        prm,
                        ' '))

            return msg, tot, prm

        print(self.nome + ' ????: ' + utili.esa_da_ba(cosa, ' '))
        return 0, 0, cosa

    def stampa(self, cosa):
        risul = self.nome + ' '
        if len(cosa) >= 4:
            msg, tot = struct.unpack('<2H', cosa[:4])
            prm = cosa[4:]

            risul += quale_comando(msg) + ' '

            if tot != len(prm):
                risul += 'ERR DIM [{} != {}]: '.format(tot, len(
                    prm)) + '\n\t' + utili.esa_da_ba(prm, ' ')
            else:
                risul += '[{}]: '.format(tot) + '\n\t' + \
                    utili.esa_da_ba(prm, ' ')
        else:
            risul += '????: ' + '\n\t' + utili.esa_da_ba(cosa, ' ')

        return risul

def estrai(oper, proto, lista):
    while True:
        msg = proto.dammi_msg()
        if msg is None:
            break
        else:
            lista.append((oper, msg))


def leggi_ingresso(nfile, proto_rx, proto_tx):
    lista_op = []
    with open(nfile, 'rt') as ing:
        while True:
            riga = ing.readline()
            if not any(riga):
                break

            if 'IRP_MJ_WRITE' in riga:
                dati = leggi_dati(riga)

                proto_tx.esamina(dati)
                estrai('w', proto_tx, lista_op)
                continue

            if 'IRP_MJ_READ' in riga:
                dati = leggi_dati(riga)
                if dati is not None:
                    proto_rx.esamina(dati)
                    estrai('r', proto_rx, lista_op)
                continue

            if 'IRP_MJ_CREATE' in riga:
                lista_op.append(('o',))
                continue

            if 'IOCTL_SERIAL_SET_BAUD_RATE' in riga:
                pos = riga.find('Baud Rate:')
                if pos == -1:
                    continue

                pos += len('Baud Rate:')
                riga = riga[pos:]
                lista_op.append(('b', int(riga)))
                continue

            if 'IRP_MJ_CLOSE' in riga:
                lista_op.append(('c',))
                continue
    return lista_op


if __name__ == '__main__':
    if len(sys.argv) == 2:
        nomeing = sys.argv[1]
        nomeusc = nomeing + '.msg'

        cy_rx = PROTO_RX()
        cy_tx = PROTO_TX()

        # recupero solo quello che serve
        operazioni = leggi_ingresso(nomeing, cy_rx, cy_tx)

        # salvo operazioni
        with open(nomeusc, 'wt') as usc:
            for elem in operazioni:
                stampa(elem, usc, cy_rx, cy_tx)

    else:
        print('Passare il file di AccessPort')
