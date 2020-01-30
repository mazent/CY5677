"""
authenticated encryption
"""
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# def _crea_iv():
#     zeri = bytearray([0] * 8)
#     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
#     digest.update(bytes(zeri))
#     iv = digest.finalize()
#     return bytearray(iv[:16])
#
# # mbed-tls salva in posizione fissa
# # def _salva_dub(iv, dub):
# #     # Ultimi bit = dimensione ultimo blocco
# #     iv[15] = (iv[15] & 0xF0) + dub
# #
# # def _leggi_dub(iv):
# #     return iv[15] & 0x0F
#
# BIT_0 = 1 << 7
#
#
# def _salva_dub(iv, dub):
#     mask = 0xF0
#     dove = iv[0] & 0x07
#
#     # Questo bit mi dice in quale nibble ...
#     if iv[0] & BIT_0:
#         mask = 0x0F
#         dub <<= 4
#
#         # ... e dove prendere la posizione
#         dove = iv[0] & 0x70
#         dove >>= 4
#
#     # I bit 0/2 mi dicono in quale posizione ...
#     pos = iv[dove] & 0x07
#     # ... a partire dal centro
#     pos += 8
#
#     iv[pos] = (iv[pos] & mask) | dub
#
#
# def _leggi_dub(iv):
#     mask = 0x0F
#     dove = iv[0] & 0x07
#     shift = 0
#
#     if iv[0] & BIT_0:
#         mask <<= 4
#         shift = 4
#         dove = iv[0] & 0x70
#         dove >>= 4
#
#     pos = iv[dove] & 0x07
#     pos += 8
#
#     dub = iv[pos] & mask
#     if shift:
#         dub >>= shift
#
#     return dub


class PRIVACY:
    """
    crypt and decrypt based on a secret
    """

    def __init__(self, casuali):
        self.segreto = bytes(casuali)

    # def get_random(self, dim):
    #     return secrets.token_bytes(dim)

    def hash(self, prm):
        """
        return sha256 of prm concatenated with the secret
        :param prm: bytearray
        :return: bytes
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(prm))
        digest.update(self.segreto)
        return digest.finalize()

#     self.finta = finta
    #
    # def _chiave(self, iv):
    #     key = iv[:16]
    #     key += bytearray([0] * 16)
    #
    #     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    #     digest.update(bytes(key))
    #     digest.update(self.segreto)
    #     return digest.finalize()
    #
    # def cifra(self, cosa):
    #     if isinstance(cosa, str):
    #         cosa = bytes(cosa.encode('ascii'))
    #
    #     # creo IV
    #     if self.finta:
    #         iv = _crea_iv()
    #     else:
    #         iv = bytearray(secrets.token_bytes(16))
    #
    #     # Salvo la dimensione dell'ultimo blocco
    #     dub = len(cosa) & 0x0F
    #     _salva_dub(iv, dub)
    #
    #     iv = bytes(iv)
    #
    #     # inizializzo l'uscita
    #     uscita = bytearray(iv)
    #
    #     # Imposto la chiave
    #     key = self._chiave(iv)
    #
    #     # cifro
    #     if dub:
    #         cosa = cosa + bytes([0] * (16 - dub))
    #     cipher = Cipher(
    #         algorithms.AES(key),
    #         modes.CBC(iv),
    #         backend=default_backend())
    #     encryptor = cipher.encryptor()
    #     ct = encryptor.update(bytes(cosa)) + encryptor.finalize()
    #     uscita += ct
    #
    #     # firmo
    #     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    #     digest.update(key)
    #     digest.update(ct)
    #     uscita += digest.finalize()
    #
    #     return uscita
    #
    # def decifra(self, cosa):
    #     # scompongo
    #     iv = bytes(cosa[:16])
    #     dim = len(cosa)
    #     firma = cosa[dim - 32:]
    #     ct = bytes(cosa[16:dim - 32])
    #
    #     # dimensione ultimo blocco
    #     dub = _leggi_dub(iv)
    #
    #     # Imposto la chiave
    #     key = self._chiave(iv)
    #
    #     # Decifro
    #     cipher = Cipher(
    #         algorithms.AES(key),
    #         modes.CBC(iv),
    #         backend=default_backend())
    #     decryptor = cipher.decryptor()
    #     pt = decryptor.update(ct) + decryptor.finalize()
    #
    #     # Calcolo la firma
    #     digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    #     digest.update(key)
    #     digest.update(ct)
    #     firma_calc = digest.finalize()
    #
    #     if firma == firma_calc:
    #         dim = len(pt)
    #         if dub:
    #             dim -= 16
    #             dim += dub
    #
    #         return pt[:dim]
    #
    #     return None

if __name__ == '__main__':
    import utili

    un_segreto = bytes(
        [
            0x40, 0xEE, 0x5C, 0x9A, 0xF6, 0x08, 0x81, 0x50,
            0x15, 0xC4, 0x9B, 0x1E, 0xFF, 0x43, 0xCC, 0xFB,
            0x65, 0x40, 0x3E, 0xD1, 0xDA, 0xF0, 0x78, 0x51,
            0xC3, 0x65, 0xB5, 0xA6, 0x48, 0x1A
        ]
    )

    #sicurezza = PRIVACY(un_segreto, finta=True)
    sicurezza = PRIVACY(un_segreto)
    testo = 'ciao'
    for _ in range(10):
        ct = sicurezza.cifra(testo)
        utili.StampaEsa(ct, 'ct: ')

        pt = sicurezza.decifra(ct)
        x = str(pt.decode('ascii'))
        print(testo == x)

    crono = utili.CRONOMETRO()
    quante = 1000
    crono.conta()
    for _ in range(quante):
        ct = sicurezza.cifra(testo)
        pt = sicurezza.decifra(ct)
    durata = crono.durata()
    durata *= 1000.0
    print('{} giri completi in '.format(quante) + utili.stampaDurata(durata))
    una = durata / (quante * 2.0)
    print('uno in {:.3f} ms'.format(una))
