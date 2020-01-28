"""
    Contiene:
        *) L'implementazione della comunicazione bt con 220_demo via CY567x
        *) Un test di comunicazione
"""

import time
#import queue

import CY567x
import utili



class GHOST(CY567x.CY567x):
    """
        implementa la comunicazione bt con 220-demo via CY567x
    """

    def __init__(self, porta=None):
        self.authReq = False
        self.pairReq = False

        super().__init__(self, porta=porta)

        try:
            if not DISPO.init_ble_stack():
                raise utili.Problema('err init')

            if not DISPO.set_device_io_capabilities('KEYBOARD DISPLAY'):
                raise utili.Problema('err capa')

            if not DISPO.set_local_device_security('3'):
                raise utili.Problema('err security')
        except utili.Problema as err:
            print(err)

    def gap_auth_req_cb(self, ai):
        self.authReq = True

    def gap_passkey_entry_request_cb(self):
        self.pairReq = True


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

    if DISPO.is_ok():
        try:
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

            if not DISPO.pairing_passkey(123456):
                raise utili.Problema('err passkey')

        except utili.Problema as err:
            print(err)

        time.sleep(5)

        DISPO.disconnect()
        DISPO.close()
