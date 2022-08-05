import sys

import utili
from cyproto import PROTO_RX, PROTO_TX


def leggi_dati(riga):
    # inizia con: "2022-08-05 09:59:06,027 - ..."
    pos = riga.find(' ')
    if pos == -1:
        return None
    pos = riga.find('-', pos)
    if pos == -1:
        return None
    quando = riga[:pos]
    quando = quando.rstrip(' \t\r\n')

    pos = riga.find('Data:')
    if pos == -1:
        return None

    pos += 6
    riga = riga[pos:]
    riga = riga.rstrip(' \t\r\n')

    return quando, utili.ba_da_esa(riga, ' ')


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

    if 'w' in cosa[0]:
        pos = cosa[0].find('w')
        quando = cosa[0][:pos]

        dove.write(quando)
        dove.write(proto_tx.msg_to_string(cosa[1]))
        dove.write('\n')
        return

    if 'r' in cosa[0]:
        pos = cosa[0].find('r')
        quando = cosa[0][:pos]

        dove.write(quando)
        dove.write(proto_rx.msg_to_string(cosa[1]))
        dove.write('\n')
        return

    dove.write('???\n')


def estrai(oper, proto, lista):
    while True:
        msg = proto.get_msg()
        if msg is None:
            break

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
                if dati is None:
                    continue

                proto_tx.examine(dati[1])
                estrai(dati[0] + ' w', proto_tx, lista_op, )
                continue

            if 'IRP_MJ_READ' in riga:
                dati = leggi_dati(riga)
                if dati is None:
                    continue

                proto_rx.examine(dati[1])
                estrai(dati[0] + ' r', proto_rx, lista_op)
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
        nomeusc = nomeing + '.txrx'

        cy_rx = PROTO_RX()
        cy_tx = PROTO_TX()

        # recupero solo quello che serve
        operazioni = leggi_ingresso(nomeing, cy_rx, cy_tx)

        # salvo operazioni
        with open(nomeusc, 'wt') as usc:
            for elem in operazioni:
                stampa(elem, usc, cy_rx, cy_tx)

    else:
        print('Passare il file del diario')
