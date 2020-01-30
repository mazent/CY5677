"""
Collects utilities to break scan reports
"""
import struct
import uuid

import utili


def scan_report(data):
    """
    utility to decompose a report (cfr Send_advt_report)
    :param data: bytearray
    :return: dict
    """
    sr = {
        'adv_type': _ADVERTISEMENT_EVENT_TYPE[data[0]],
        'bda': utili.str_da_mac(data[1:7])
    }

    bda_type, rssi, dim = struct.unpack('<BbB', data[7:10])
    sr['bda_type'] = _ADDRESS_TYPE[bda_type]
    sr['rssi'] = rssi
    sr['data'] = data[10:]
    if len(sr['data']) != dim:
        sr['err'] = 'dim'

    return sr


def _at_flags(data):
    return 'flags', data


def _at_manufacturer(data):
    # The first 2 octets contain the Company Identifier Code
    # https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/
    cic = struct.unpack('<H', data[:2])
    return 'manuf', cic[0], data[2:]


def _at_service_data16(data):
    sid = struct.unpack('<H', data[:2])
    data = data[2:]
    return 'srvd16', sid, data


def _at_service_data32(data):
    sid = struct.unpack('<I', data[:4])
    data = data[4:]
    return 'srvd32', sid, data


def _at_service_data128(data):
    sid = data[:16]
    data = data[16:]

    sid.reverse()
    sid = uuid.UUID(bytes=bytes(sid))
    return 'srvd32', str(sid).upper(), data


def _at_name(data):
    return 'name', data.decode('ascii')


def _at_tx_power(data):
    txp = struct.unpack('<b', data)
    return 'txp', txp[0]


def _at_service_class_uuid128(data):
    data.reverse()
    srv = uuid.UUID(bytes=bytes(data))
    return 'srv128', str(srv).upper()


def _at_service_class_uuid16(data):
    srv = struct.unpack('<H', data)[0]
    return 'srv16', '{:04X}'.format(srv)


def _at_service_class_uuid32(data):
    srv = struct.unpack('<I', data)[0]
    return 'srv32', '{:04X}'.format(srv)


def scan_advertise(data):
    """
    utility to decompose an advertise
    references:
        bt 4.2, vol 3, part C, 11 (pag 2081)
        https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile
    :param data: bytearray
    :return: list of tuples (type, ...)
    """
    adv = []
    while len(data):
        # structure length
        slen = data.pop(0)
        # structure data
        sdata = data[:slen]
        # next structures
        data = data[slen:]

        # structure type
        stype = sdata.pop(0)
        try:
            adv.append(_ADV_TYPE[stype](sdata))
        except KeyError:
            adv.append(('???', stype, sdata))
    return adv


_ADV_TYPE = {
    0x01: _at_flags,
    0xFF: _at_manufacturer,
    0x0A: _at_tx_power,
    # incomplete
    0x02: _at_service_class_uuid16,
    # complete
    0x03: _at_service_class_uuid16,
    # incomplete
    0x04: _at_service_class_uuid32,
    # complete
    0x05: _at_service_class_uuid32,
    # incomplete
    0x06: _at_service_class_uuid128,
    # complete
    0x07: _at_service_class_uuid128,
    # short
    0x08: _at_name,
    # complete
    0x09: _at_name,
    # 128 bit
    0x21: _at_service_data128,
    # 32 bit
    0x20: _at_service_data32,
    # 16 bit
    0x16: _at_service_data16
}

_ADVERTISEMENT_EVENT_TYPE = {
    0x00: 'Connectable undirected advertising',
    0x01: 'Connectable directed advertising',
    0x02: 'Scannable undirected advertising',
    0x03: 'Non connectable undirected advertising',
    0x04: 'Scan Response'
}

_ADDRESS_TYPE = {
    0x00: 'Public Device Address',
    0x01: 'Random Device Address',
    0x02: 'Public Resolvable Address',
    0x03: 'Random Resolvable Address'
}
