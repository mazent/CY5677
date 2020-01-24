"""
    Contiene:
        *) L'implementazione della comunicazione bt con 220_demo via CY5677
        *) Un test di comunicazione
"""

import time
#import queue

import cy5677
import utili

class GHOST(cy5677.CY5677):
    """
        implementa la comunicazione bt con 220-demo via CY5677
    """

    def __init__(self, porta=None):
        cy5677.CY5677.__init__(self, porta=porta)
        #self.rsp = queue.Queue()

    def notification(self, rsp):
        """
            overriding per ricevere le notifiche, cioe' le risposte
        :param rsp: il dizionario con la notifica
        :return:
        """
        print('[{:04X}] -> {}'.format(rsp['crt'], rsp['ntf'].decode('ascii')))



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
    argom.add_argument('mac', help="L'indirizzo del dispositivo (xx:yy:..ww)")
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

    MAC = arghi.mac
    MTU = arghi.mtu
    # DIM = arghi.dim
    # NUM = arghi.num
    # criterio = lambda cnt, lim: True
    # if NUM:
    #     criterio = lambda cnt, lim: cnt < lim

    # test
    DISPO = GHOST()

    if DISPO.a_posto():
        try:
            if not DISPO.connect(MAC):
                raise utili.Problema('err connect')
            print('connesso')

            if not DISPO.exchange_mtu_size(MTU):
                raise utili.Problema('err mtu')
            print('mtu {}'.format(MTU))

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        DISPO.disconnect()
        DISPO.chiudi()
