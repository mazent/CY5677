import queue
import struct
import threading

import serial

import utili

BAUD_CY5670 = 115200
BAUD_CY5677 = 921600

# py -> cy5677


Cmd_Init_Ble_Stack_Api = 0xFC07
_CMD_START_SCAN = 0xFE93
_CMD_STOP_SCAN = 0xFE94
Cmd_Establish_Connection_Api = 0xFE97
_CMD_TERMINATE_CONNECTION = 0xFE98
_CMD_EXCHANGE_GATT_MTU_SIZE = 0xFE12
_CMD_READ_CHAR_VALUE = 0xFE06
_CMD_READ_LONG_CHARACTERISTIC_VALUES = 0xFE08
_CMD_READ_CHAR_DESCRIPTOR = 0xFE0E
Cmd_Initiate_Pairing_Request_Api = 0xFE99

_CMD_GATT_WRITECHARVAL_WR = (4 << 7) + 10
_CMD_GATT_WRITECHARVAL = (4 << 7) + 11
_CMD_GATT_WRITE_LONG = (4 << 7) + 12

# cy5677 -> py
_HEADER_RSP = 0xA7BD

_EVT_COMMAND_STATUS = 0x047E
_EVT_COMMAND_COMPLETE = 0x047F
_EVT_SCAN_PROGRESS_RESULT = 0x068A
_EVT_SCAN_STOPPED_NOTIFICATION = 0x0691
_EVT_ESTABLISH_CONN_RESP = 0x068F
_EVT_ENHANCED_CONN_COMP = 0x06A0
_EVT_DATA_LEN_CHG_NOTIF = 0x069D
_EVT_EXCHANGE_MTU_SIZE_RESP = 0x060F
_EVT_CHAR_VALUE_NOTIF = 0x060C
_EVT_CONN_TERM_NOTIF = 0x0690
_EVT_READ_CHAR_DESC_RESP = 0x060A
_EVT_READ_CHAR_VALUE_RESP = 0x0606
_EVT_READ_LONG_CHAR_VALUE_RESP = 0x0608
_EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION = 0x0692

_DESC_EVT = {
    0x068A: 'Scan Progress Result',
    0x0691: 'Scan Stopped Notification',
    0x068F: 'Establish Connection Response',
    0x06A0: 'Enhanced Connection Complete',
    0x069D: 'Data Length Changed Notification',
    0x0699: 'Get Local Device Security Keys Response',
    0x060F: 'Exchange Gatt Mtu Size Response',
    0x0607: 'Read Using Characteristic Uuid Response',
    0x060C: 'Characteristic Value Notification'
}


def _evt_cmd_sttcmplt(rsp):
    cmd, stt = struct.unpack('<2H', rsp['altro'])
    del rsp['altro']
    rsp['cmd'] = cmd
    rsp['stt'] = stt


class CY5677(threading.Thread):
    """
        Fornisce i comandi di base per la comunicazione ble
    """


    def _risposta(self):
        """
        preleva dalla seriale una risposta (evento, cmd status, cmd complete)
        :return: dizionario con la risposta
        """
        while True:
            # almeno fino all'evento
            rx = self.uart.read(6)
            if len(rx) == 0:
                return None

            print('IRP_MJ_READ Data: ' + utili.esa_da_ba(rx, ' '))

            if len(rx) < 6:
                print('err < 6 <{}>'.format(rx.hex()))
                return None

            hrsp, tot, evt = struct.unpack('<3H', rx)
            if hrsp != _HEADER_RSP:
                print('err hrsp <{}>'.format(rx.hex()))
                continue

            rsp = {
                'evt': evt
            }

            if tot > 2:
                tot -= 2

                altro = b''
                while True:
                    letti = self.uart.read(tot)
                    if len(letti) == 0:
                        print(
                            'attesi {} ricevuti 0 <{}.{}>'.format(
                                tot, rx.hex(), altro.hex()))
                        return None
                    print('IRP_MJ_READ Data: ' + utili.esa_da_ba(letti, ' '))
                    altro += letti
                    if len(letti) == tot:
                        break
                    tot -= len(letti)

                rsp['altro'] = altro

                # provo a vedere il tipo di evento
                LISTA = {
                    _EVT_COMMAND_STATUS: _evt_cmd_sttcmplt,
                    _EVT_COMMAND_COMPLETE: _evt_cmd_sttcmplt
                }
                try:
                    LISTA[evt](rsp)
                except KeyError:
                    # print('?{:04X}? <{}>'.format(evt, altro.hex()))
                    pass

            return rsp

    def _establish_conn_resp(self, rsp):
        self.cyBle_connHandle = rsp['altro'][2:]

    def _data_len_chg_notif(self, _):
        self._fine_comando()

    def _conn_term_notif(self, rsp):
        cyBle_connHandle = rsp['altro'][:2]
        eventParam = rsp['altro'][2:]
        if self.cyBle_connHandle == cyBle_connHandle:
            print(
                'chiusa {} per {}'.format(
                    cyBle_connHandle.hex(),
                    eventParam.hex()))
            self.cyBle_connHandle = None
            self.mtu = 23
            self._fine_comando()
        else:
            print(
                '_EVT_CONNECTION_TERMINATED_NOTIFICATION: err conn handle')

    def _enhanced_connection_complete(self, _):
        """
        EVT_ENHANCED_CONNECTION_COMPLETE [34]: evento inutile
        97 FE               comando
        00 					connParam->status
        04 00 				cyBle_connHandle
        00 					connParam->role
        00 					connParam->masterClockAccuracy
        2D A4 C4 50 A0 00 	connParam->peerBdAddr
        00 					connParam->peerBdAddrType
        00 00 00 00 00 00 	connParam->localResolvablePvtAddr
        01 					addrType (dummy)
        00 00 00 00 00 00 	connParam->peerResolvablePvtAddr
        01 	  				addrType (dummy)
        07 00 				connParam->connIntv
        00 00 				connParam->connLatency
        0A 00 				connParam->supervisionTo
        """

    def _cyble_evt_gap_auth_req(self, rsp):
        """
        EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION [7]: inutile
        04 00 	cyBle_connHandle
                CYBLE_GAP_AUTH_INFO_T
        02 		security
        00 		bonding
        07 		ekeySize
        00 		authErr
        00		pairingProperties
        """
        _, security, bonding, ekeySize, _, pairingProperties = struct.unpack('<H5B', rsp['altro'])
        prm = {
            'security': security,
            'bonding': bonding,
            'ekeySize': ekeySize,
            'pairingProperties': pairingProperties
        }
        self.evt_gap_auth_req(prm)

    def _command_status(self, rsp):
        if rsp['cmd'] in (_CMD_START_SCAN, Cmd_Initiate_Pairing_Request_Api):
            self._fine_comando()

    def _command_complete(self, rsp):
        if rsp['cmd'] in (
                _CMD_GATT_WRITECHARVAL,
                _CMD_EXCHANGE_GATT_MTU_SIZE,
                _CMD_GATT_WRITECHARVAL_WR,
                _CMD_GATT_WRITE_LONG):
            self._fine_comando()
        elif rsp['cmd'] == _CMD_READ_LONG_CHARACTERISTIC_VALUES:
            self._fine_comando_con_dati(None)

    def _exchange_mtu_size_resp(self, rsp):
        # cmd
        _ = rsp['altro'][:2]
        cyBle_connHandle = rsp['altro'][2:4]
        if self.cyBle_connHandle == cyBle_connHandle:
            eventParam = rsp['altro'][4:]
            mtu = struct.unpack('<H', eventParam)
            self.mtu = mtu[0]
        else:
            print('_EVT_EXCHANGE_GATT_MTU_SIZE_RESPONSE: err conn handle')

    def _char_value_notif(self, rsp):
        self._evn_notif(rsp)
        self.notification(rsp)

    def _read_char_desc_resp(self, rsp):
        # cmd
        _ = rsp['altro'][:2]
        cyBle_connHandle = rsp['altro'][2:4]
        if self.cyBle_connHandle == cyBle_connHandle:
            # dim
            _ = rsp['altro'][4:6]
            desc = rsp['altro'][6:]
            self._fine_comando_con_dati(desc.decode('ascii'))
        else:
            print(
                '_EVT_READ_CHARACTERISTIC_DESCRIPTOR_RESPONSE: err conn handle')

    def _read_char_value_resp(self, rsp):
        # cmd
        _ = rsp['altro'][:2]
        cyBle_connHandle = rsp['altro'][2:4]
        if self.cyBle_connHandle == cyBle_connHandle:
            # dim
            _ = rsp['altro'][4:6]
            val = rsp['altro'][6:]
            self._fine_comando_con_dati(val)

    def _read_long_char_value_resp(self, rsp):
        # cmd
        _ = rsp['altro'][:2]
        cyBle_connHandle = rsp['altro'][2:4]
        if self.cyBle_connHandle == cyBle_connHandle:
            # dim
            _ = rsp['altro'][4:6]
            val = rsp['altro'][6:]
            dati = self.cmd_corr[2]
            dati += val

    def _scan_progress_result(self, rsp):
        rep = self.scan_report(rsp['altro'][2:])
        if self.scan_cb is not None:
            self.scan_cb(rep)
        else:
            print('? scan report ?')

    def _scan_stopped_notification(self, _):
        self._fine_comando(True)
        self.scan_cb = None

    @staticmethod
    def _stampa_risposta(rsp):

        def desc_evn(evn):
            try:
                return _DESC_EVT[evn] + '({:04X}) '.format(evn)
            except KeyError:
                return 'evt {:04X} '.format(evn)

        if rsp is not None:
            riga = desc_evn(rsp['evt'])

            if 'cmd' in rsp:
                riga = riga + \
                    'cmd {:04X} stt {:04X} '.format(rsp['cmd'], rsp['stt'])

            if 'altro' in rsp:
                riga = riga + '<{}>'.format(rsp['altro'].hex())

            print(riga)

    @staticmethod
    def _evn_cmd_XXX(cmd, rsp, evt):
        """
        verifica che la risposta ricevuta sia l'evento atteso
        :param cmd: il comando inviato precedentemente
        :param rsp: la risposta (esito di _risposta)
        :return:
        """
        try:
            if rsp['evt'] != evt:
                raise utili.Problema('evt != {}'.format(evt))

            if rsp['cmd'] != cmd:
                raise utili.Problema('altro comando')

            if rsp['stt'] != 0:
                raise utili.Problema(
                    'err {} (cfr CYBLE_API_RESULT_T in BT_Stack.h)'.format(
                        rsp['stt']))

            return True
        except (utili.Problema, KeyError) as err:
            print(err)
            return False

    @staticmethod
    def _evn_notif(rsp):
        # conn, crt, dim
        _, crt, _ = struct.unpack('<3H', rsp['altro'][:6])
        rsp['crt'] = crt
        rsp['ntf'] = rsp['altro'][6:]
        del rsp['altro']

    def __init__(self, BAUD=BAUD_CY5677, poll=0.1, porta=None):
        self._ESEGUI_CMD = {
            Cmd_Init_Ble_Stack_Api: self._init_ble,
            _CMD_START_SCAN: self._scanna,
            _CMD_STOP_SCAN: self._non_scannare,
            Cmd_Establish_Connection_Api: self._connetti,
            _CMD_TERMINATE_CONNECTION: self._sconnetti,
            _CMD_EXCHANGE_GATT_MTU_SIZE: self._mtu,
            _CMD_READ_CHAR_DESCRIPTOR: self._read_car_desc,
            _CMD_READ_CHAR_VALUE: self._read_car_value,
            _CMD_READ_LONG_CHARACTERISTIC_VALUES: self._read_car_long_value,
            _CMD_GATT_WRITECHARVAL: self._scrivi,
            _CMD_GATT_WRITECHARVAL_WR: self._scrivi_wr,
            _CMD_GATT_WRITE_LONG: self._scrivi_lungo,
        }

        self.EVENTI = {
            _EVT_ESTABLISH_CONN_RESP: self._establish_conn_resp,
            _EVT_ENHANCED_CONN_COMP: self._enhanced_connection_complete,
            _EVT_DATA_LEN_CHG_NOTIF: self._data_len_chg_notif,
            _EVT_CONN_TERM_NOTIF: self._conn_term_notif,
            _EVT_COMMAND_STATUS: self._command_status,
            _EVT_COMMAND_COMPLETE: self._command_complete,
            _EVT_EXCHANGE_MTU_SIZE_RESP: self._exchange_mtu_size_resp,
            _EVT_CHAR_VALUE_NOTIF: self._char_value_notif,
            _EVT_READ_CHAR_DESC_RESP: self._read_char_desc_resp,
            _EVT_READ_CHAR_VALUE_RESP: self._read_char_value_resp,
            _EVT_READ_LONG_CHAR_VALUE_RESP: self._read_long_char_value_resp,
            _EVT_SCAN_PROGRESS_RESULT: self._scan_progress_result,
            _EVT_SCAN_STOPPED_NOTIFICATION: self._scan_stopped_notification,
            _EVT_PAIRING_REQUEST_RECEIVED_NOTIFICATION: self._cyble_evt_gap_auth_req
        }

        self.scan_cb = None
        self.poll = poll
        self.proto = PROTO()

        try:
            serial_open = serial.Serial
            if porta is None:
                porta = 'hwgrep://04B4:F139'
                serial_open = serial.serial_for_url

            self.uart = serial_open(
                porta,
                baudrate=BAUD,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1,
                rtscts=True)

            self.mtu = 23
            self.cmd_corr = None

            self.cyBle_connHandle = None

            self.coda_cmd = queue.Queue()
            # mando io il comando che inizializza
            self.coda_cmd.put_nowait((Cmd_Init_Ble_Stack_Api, None))

            # posso girare
            threading.Thread.__init__(self)
            self.start()

        except serial.SerialException as err:
            print(err)
            self.uart = None

    def __del__(self):
        self.chiudi()

    def _init_ble(self):
        # inizializzo
        cmd = Cmd_Init_Ble_Stack_Api
        msg = self.proto.componi(cmd)

        self.uart.flushInput()
        self.uart.write(msg)

        rsp = self._risposta()
        self._evn_cmd_XXX(cmd, rsp, _EVT_COMMAND_STATUS)
        rsp = self._risposta()
        self._evn_cmd_XXX(cmd, rsp, _EVT_COMMAND_COMPLETE)

    def _connetti(self, prm):
        cod = Cmd_Establish_Connection_Api
        msg = self.proto.componi(cod, prm[0])

        self.cmd_corr = (cod, prm[1])

        self.uart.write(msg)

    def _sconnetti(self, prm):
        cod = _CMD_TERMINATE_CONNECTION
        msg = self.proto.componi(cod, self.cyBle_connHandle)

        self.cmd_corr = (cod, prm)

        self.uart.write(msg)

    def _scrivi(self, prm):
        cod = _CMD_GATT_WRITECHARVAL
        msg = self.proto.componi(cod, prm[0])

        self.cmd_corr = (cod, prm[1])

        self.uart.write(msg)

    def _scrivi_wr(self, prm):
        cod = _CMD_GATT_WRITECHARVAL_WR
        msg = self.proto.componi(cod, prm[0])

        self.cmd_corr = (cod, prm[1])

        self.uart.write(msg)

    def _scrivi_lungo(self, prm):
        cod = _CMD_GATT_WRITE_LONG
        msg = self.proto.componi(cod, prm[0])

        self.cmd_corr = (cod, prm[1])

        self.uart.write(msg)

    def _mtu(self, prm):
        cod = _CMD_EXCHANGE_GATT_MTU_SIZE
        tmp = bytearray(self.cyBle_connHandle)
        tmp += prm[0]
        msg = self.proto.componi(cod, tmp)

        self.cmd_corr = (cod, prm[1])
        self.uart.write(msg)

    def _read_car_desc(self, prm):
        cod = _CMD_READ_CHAR_DESCRIPTOR
        tmp = bytearray(self.cyBle_connHandle)
        tmp += prm[0]
        msg = self.proto.componi(cod, tmp)

        self.cmd_corr = (cod, prm[1])
        self.uart.write(msg)

    def _read_car_value(self, prm):
        cod = _CMD_READ_CHAR_VALUE
        tmp = bytearray(self.cyBle_connHandle)
        tmp += prm[0]
        msg = self.proto.componi(cod, tmp)

        self.cmd_corr = (cod, prm[1])
        self.uart.write(msg)

    def _read_car_long_value(self, prm):
        cod = _CMD_READ_LONG_CHARACTERISTIC_VALUES
        tmp = bytearray(self.cyBle_connHandle)
        tmp += prm[0]
        msg = self.proto.componi(cod, tmp)

        self.cmd_corr = (cod, prm[1], bytearray())
        self.uart.write(msg)

    def _scanna(self, prm):
        cod = _CMD_START_SCAN
        msg = self.proto.componi(cod)

        self.scan_cb = prm[0]
        self.cmd_corr = (cod, prm[1])
        self.uart.write(msg)

    def _non_scannare(self, prm):
        cod = _CMD_STOP_SCAN
        msg = self.proto.componi(cod)

        self.cmd_corr = (cod, prm)
        self.uart.write(msg)

    def _fine_comando(self, esito=True):
        if self.cmd_corr is not None:
            coda = self.cmd_corr[1]
            coda.put_nowait(esito)
            self.cmd_corr = None

    def _fine_comando_con_dati(self, dati):
        if self.cmd_corr is not None:
            coda = self.cmd_corr[1]
            if dati is None:
                dati = self.cmd_corr[2]
            coda.put_nowait(dati)
            self.cmd_corr = None

    def run(self):
        while True:
            # attesa comandi
            try:
                # cmd = (codice, parametro)
                cmd = self.coda_cmd.get(True, self.poll)

                if cmd[0] == 0xE5C1:
                    break

                funz = self._ESEGUI_CMD[cmd[0]]
                if cmd[1] is None:
                    funz()
                else:
                    funz(cmd[1])

            except (queue.Empty, KeyError) as err:
                if isinstance(err, KeyError):
                    print('comando sconosciuto')

            # polling della seriale
            while self.uart.in_waiting:
                tmp = self.uart.read(self.uart.in_waiting)
                if len(tmp) == 0:
                    break
                self.proto.da_esaminare(tmp)

            # esamino il raccolto
            while True:
                rsp = self.proto.risposta()
                if rsp is None:
                    break

                try:
                    self.EVENTI[rsp['evt']](rsp)
                except KeyError:
                    self._stampa_risposta(rsp)

    def chiudi(self):
        """
        termina il ddd e chiude la seriale
        :return: Niente
        """
        if self.uart is not None:
            # ammazzo il ddd
            cod = 0xE5C1
            self.coda_cmd.put_nowait((cod, None))

            # aspetto
            self.join()

            # chiudo
            self.uart.close()
            self.uart = None

    def a_posto(self):
        """
        permette di capire se la seriale e' stata aperta correttamente
        :return: bool
        """
        return self.uart is not None

    @staticmethod
    def scan_report(adv):
        """
        spacca un advertise (cfr Send_advt_report)
        :param adv: dati dell'advertise
        :return: scan report
        """
        _sr = {
            'tipo': adv[0],
            'bda': adv[1:7]
        }

        tipo_bda, _rssi, dim = struct.unpack('<BbB', adv[7:10])
        _sr['tipo_bda'] = tipo_bda
        _sr['rssi'] = _rssi
        if len(adv) > 10:
            _sr['dati'] = adv[10:]
            if len(_sr['dati']) != dim:
                _sr['err'] = 'dim dati'

        return _sr

    def scan(self, cb):
        """
        inizia la scansione
        :param cb: callback per i scan report
        :return: bool
        """
        cod = _CMD_START_SCAN
        esito = queue.Queue()
        self.coda_cmd.put_nowait((cod, (cb, esito)))

        try:
            return esito.get(True, 5)
        except queue.Empty:
            return False

    def stop_scan(self):
        """
        termina la scansione
        :return: niente
        """
        if self.scan_cb is None:
            return True

        cod = _CMD_STOP_SCAN
        esito = queue.Queue()
        self.coda_cmd.put_nowait((cod, esito))

        try:
            return esito.get(True, 5)
        except queue.Empty:
            return False

    def connect(self, strmac, public=True):
        """
        tenta di connettersi al dispositivo indicato
        :param strmac: indirizzo umano (ascii, rovescio)
        :return: bool
        """
        if self.cyBle_connHandle is not None:
            return False

        _mac = utili.mac_da_str(strmac)

        _mac.append(0 if public else 1)

        cod = Cmd_Establish_Connection_Api
        esito = queue.Queue()
        prm = (_mac, esito)
        self.coda_cmd.put_nowait((cod, prm))

        try:
            _ = esito.get(True, 5)

            return self.cyBle_connHandle is not None
        except queue.Empty:
            print('conn timeout!!')
            return False

    def exchange_mtu_size(self, mtu):
        """
        cambia l'mtu (o ci prova)
        :param mtu: desiderata
        :return: bool
        """
        if self.cyBle_connHandle is None:
            return False

        tmp = struct.pack('<H', mtu)

        cod = _CMD_EXCHANGE_GATT_MTU_SIZE
        esito = queue.Queue()
        self.coda_cmd.put_nowait((cod, (tmp, esito)))

        try:
            return esito.get(True, 5)
        except queue.Empty:
            print('mtu timeout!!')
            return False

    def current_mtu(self):
        """
        ottiene l'mtu attuale
        :return: mtu
        """
        return self.mtu

    def gap_auth_req(self):
        """
        Initiate authentication procedure

        Used after receiving CYBLE_EVT_GAP_AUTH_REQ
        :return: bool
        """
        if self.cyBle_connHandle is None:
            return False

        cod = Cmd_Initiate_Pairing_Request_Api
        esito = queue.Queue()
        self.coda_cmd.put_nowait((cod, esito))

        try:
            _ = esito.get(True, 5)

            return self.cyBle_connHandle is None
        except queue.Empty:
            print('disc timeout!!')
            return False

    def disconnect(self):
        """
        chiude la connessione
        :return: bool
        """
        if self.cyBle_connHandle is None:
            return True

        cod = _CMD_TERMINATE_CONNECTION
        esito = queue.Queue()
        self.coda_cmd.put_nowait((cod, esito))

        try:
            _ = esito.get(True, 5)

            return self.cyBle_connHandle is None
        except queue.Empty:
            print('disc timeout!!')
            return False

    def write(self, crt, dati, cod=_CMD_GATT_WRITECHARVAL):
        """
        scrive il valore di una caratteristica

        :param crt: handle della caratteristica
        :param dati: bytearray da scrivere
        :return: bool
        """
        if self.cyBle_connHandle is None:
            return False

        if len(dati) > self.mtu - 3:
            dati = dati[:self.mtu - 3]

        esito = queue.Queue()

        prm = bytearray(self.cyBle_connHandle)
        prm += struct.pack('<HH', crt, len(dati))
        prm += dati

        self.coda_cmd.put_nowait((cod, (prm, esito)))

        try:
            return esito.get(True, 5)
        except queue.Empty:
            print('write timeout!!')
            return False

    def write_N(self, crt, dati):
        """
        scrive il valore di una caratteristica

        se ci sono troppi dati, spezzetta in piu' scritture

        :param crt: handle della caratteristica
        :param dati: bytearray da scrivere
        :return: bool
        """
        esito = True
        while len(dati) and esito:
            dim = min(self.mtu - 3, len(dati))

            esito = self.write(crt, dati[:dim])
            dati = dati[dim:]

        return esito

    def write_without_response(self, crt, dati):
        """
        esegue l'omonima procedura
        :param crt: handle della caratteristica
        :param dati: bytearray da scrivere
        :return: bool
        """

        return self.write(crt, dati, _CMD_GATT_WRITECHARVAL_WR)

    def write_long(self, crt, dati, ofs=0):
        """
        esegue l'omonima procedura
        :param crt: handle della caratteristica
        :param dati: bytearray da scrivere
        :param ofs: eventuale posizione
        :return: bool
        """
        cod = _CMD_GATT_WRITE_LONG
        esito = queue.Queue()

        prm = bytearray(self.cyBle_connHandle)
        prm += struct.pack('<3H', crt, ofs, len(dati))
        prm += dati

        self.coda_cmd.put_nowait((cod, (prm, esito)))

        try:
            return esito.get(True, 5)
        except queue.Empty:
            print('write long timeout!!')
            return False

    def read(self, crt, cod=_CMD_READ_CHAR_VALUE):
        """
        legge il valore di una caratteristica (max mtu-1)
        :param crt: handle della caratteristica
        :return: bytearray col valore
        """
        if self.cyBle_connHandle is None:
            return None

        esito = queue.Queue()

        prm = struct.pack('<H', crt)

        self.coda_cmd.put_nowait((cod, (prm, esito)))
        try:
            return esito.get(True, 5)
        except queue.Empty:
            print('read timeout!!')
            return None

    def read_desc(self, crt):
        """
            legge la descrizione di una caratteristica
        :param crt: handle della caratteristica
        :return: descrizione (ascii)
        """
        return self.read(crt, _CMD_READ_CHAR_DESCRIPTOR)

    def read_long(self, crt, ofs=0):
        """
        legge il valore di una caratteristica (qls mtu + offset)
        :param crt:
        :return:
        """
        if self.cyBle_connHandle is None:
            return None

        cod = _CMD_READ_LONG_CHARACTERISTIC_VALUES
        esito = queue.Queue()

        prm = struct.pack('<HH', crt, ofs)

        self.coda_cmd.put_nowait((cod, (prm, esito)))
        try:
            return esito.get(True, 5)
        except queue.Empty:
            print('read long timeout!!')
            return None

    def notification(self, rsp):
        """
        sostituire (override) questo metodo per
        riceve le notifiche
        :param rsp: dizionario con:
                    'evt': inutile
                    'crt': handle della caratteristica notificata
                    'ntf': contenuto della notifica
        :return: niente
        """
        print('[{:04X}] -> {}'.format(rsp['crt'], rsp['ntf'].decode('ascii')))

    def evt_gap_auth_req(self, prm):
        """
        Override this method to receive CYBLE_EVT_GAP_AUTH_REQ

        Central needs to call CyBle_GappAuthReq() to initiate authentication procedure

        :param prm: dictionary with keys:
                    'security'              CYBLE_GAP_AUTH_INFO_T.security
                    'bonding'               CYBLE_GAP_AUTH_INFO_T.bonding
                    'ekeySize'              CYBLE_GAP_AUTH_INFO_T.ekeySize
                    'pairingProperties'     CYBLE_GAP_AUTH_INFO_T.pairingProperties
        :return: None
        """
        print('CYBLE_EVT_GAP_AUTH_REQ: ')
        print('\tsecurity={:02X}'.format(prm['security']))
        print('\tbonding={}'.format(prm['bonding']))
        print('\tekeySize={}'.format(prm['ekeySize']))
        print('\tpairingProperties={}'.format(prm['pairingProperties']))


if __name__ == '__main__':
    # Esempio di uso: scansione
    import operator
    import argparse

    # argomenti
    argom = argparse.ArgumentParser(
        description='Scansione dei dispositivi ble')
    argom.add_argument('--secondi', '-s', type=int, default=5,
                       help='durata in secondi (5)')
    arghi = argom.parse_args()

    def stampa_report(_sr):
        """
        indovina
        :param _sr: scan report
        :return: niente
        """
        TIPO = {
            0: 'Connectable undirected advertising',
            1: 'Connectable directed advertising',
            2: 'Scannable undirected advertising',
            3: 'Non connectable undirected advertising',
            4: 'Scan Response',
        }
        MAC = {
            0: 'Public Device Address',
            1: 'Random Device Address',
            2: 'Public Resolvable Private Address',
            3: 'Random Resolvable Private Address',
        }

        print('scan report')
        if _sr['tipo'] in TIPO:
            print('\t' + TIPO[_sr['tipo']])
        else:
            print('\t? tipo {} ?'.format(_sr['tipo']))
        if _sr['tipo_bda'] in MAC:
            print('\tmac: ' +
                  utili.str_da_mac(_sr['bda']) +
                  ' ' +
                  MAC[_sr['tipo_bda']])
        else:
            print(
                '\tmac: ' +
                utili.str_da_mac(
                    _sr['bda']) +
                ' ? tipo {} ?'.format(
                    _sr['tipo_bda']))
        print('\trssi {}'.format(_sr['rssi']))
        if 'dati' in _sr:
            print('\tdati <{}>'.format(_sr['dati'].hex()))
        if 'err' in _sr:
            print('\terr nei dati')

    CODA_SR = queue.Queue()

    def callback(_sr):
        """
        invocata dal thread quando arriva uno scan report
        :param _sr: scan report
        :return: niente
        """
        CODA_SR.put_nowait(_sr)

    DONGLE = CY5677()

    def basta():
        """
        invia il comando di stop
        :return: niente
        """
        DONGLE.stop_scan()

    # quando viene eseguito invia lo stop
    TO = utili.Periodico(basta)

    try:
        if not DONGLE.a_posto():
            raise utili.Problema('non a posto')

        if not DONGLE.scan(callback):
            raise utili.Problema('ERR scan')

        TO.avvia(arghi.secondi)

        lista = {}
        try:
            while True:
                # quando finiscono i report si esce
                sr = CODA_SR.get(timeout=1)
                if sr['bda'] in lista:
                    rssi = lista[sr['bda']]
                    rssi.append(sr['rssi'])
                    lista[sr['bda']] = rssi
                else:
                    lista[sr['bda']] = [sr['rssi']]
                stampa_report(sr)
        except queue.Empty:
            pass

        TO.termina()

        if len(lista):
            lista2 = {}
            for mac, lrssi in lista.items():
                rssi = 0.0
                for x in lrssi:
                    rssi += x
                rssi = rssi / len(lrssi)
                lista2[utili.str_da_mac(mac)] = rssi

            lista3 = sorted(lista2.items(), key=operator.itemgetter(1))

            print('Vedo questi:')
            conta = 1
            for elem in lista3:
                print('{}: {} [{:.1f}]'.format(conta, elem[0], elem[1]))
                conta += 1

    except utili.Problema as err:
        print(err)

    DONGLE.chiudi()


class PROTO:
    """
    Incapsula il protocollo di comunicazione (risposte)
    """
    _HEADER_CMD = 0x5943

    def _testa(self):
        estratti = False
        if len(self.esamina) >= 6:
            rx = self.esamina[:6]
            self.esamina = self.esamina[6:]
            estratti = True

            hrsp, tot, evt = struct.unpack('<3H', rx)
            if hrsp != _HEADER_RSP:
                print('err hrsp <{}>'.format(rx.hex()))
            elif tot == 2:
                self.rsp = {
                    'evt': evt
                }
            else:
                self.prz = {
                    'evt': evt,
                    'tot': tot - 2,
                    'altro': b''
                }
                self.stato = 1
        return estratti

    def _dati(self):
        dim = min(self.prz['tot'], len(self.esamina))
        if dim == 0:
            return False

        self.prz['altro'] += self.esamina[:dim]
        self.esamina = self.esamina[dim:]
        self.prz['tot'] -= dim
        if self.prz['tot'] == 0:
            del self.prz['tot']
            self.rsp = self.prz
            self.stato = 0
        return True

    def __init__(self):
        self.esamina = b''
        self.stati = {
            0: self._testa,
            1: self._dati
        }
        self.stato = 0
        self.prz = None
        self.rsp = None

    def da_esaminare(self, dati):
        """
        passa la protocollo la roba
        :param dati: la roba
        :return: nulla
        """
        print('IRP_MJ_READ Data: ' + utili.esa_da_ba(dati, ' '))
        self.esamina += dati

    def risposta(self):
        """
        estrae una risposta dai dati raccolti (se possibile)
        :return: la risposta o None
        """
        while len(self.esamina) and self.rsp is None:
            if not self.stati[self.stato]():
                break

        if self.rsp is not None:
            # provo a vedere il tipo di evento
            LISTA = {
                _EVT_COMMAND_STATUS: _evt_cmd_sttcmplt,
                _EVT_COMMAND_COMPLETE: _evt_cmd_sttcmplt
            }
            try:
                LISTA[self.rsp['evt']](self.rsp)
            except KeyError:
                # print(self.rsp)
                pass

        rsp = self.rsp
        self.rsp = None
        return rsp

    def componi(self, cmd, prm=None):
        """
        crea un comando
        :param cmd: codice del comando
        :param prm: eventuali dati
        :return: i byte del messaggio da spedire
        """
        dim = 0
        if prm is not None:
            dim = len(prm)
        msg = struct.pack('<3H', PROTO._HEADER_CMD, cmd, dim)
        if dim:
            msg += prm

        print('IRP_MJ_WRITE Data: ' + utili.esa_da_ba(msg, ' '))

        return msg
