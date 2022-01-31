"""
authenticated encryption
"""
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# prove con iv alternati
# giv = None
# giv1 = None
# giv2 = None
# import utili


class PRIVACY:
    """
    crypt and decrypt with authenticated encryption based on a secret
    """

    _BIT_POS_DUB = 1 << 7

    def __init__(self, casuali):
        self.segreto = bytes(casuali)

    def _leggi_dub(self, iv):
        mask = 0x0F
        dove = iv[0] & 0x07
        shift = 0

        if iv[0] & self._BIT_POS_DUB:
            mask <<= 4
            shift = 4
            dove = iv[0] & 0x70
            dove >>= 4

        pos = iv[dove] & 0x07
        pos += 8

        dub = iv[pos] & mask
        if shift:
            dub >>= shift

        return dub

    def _salva_dub(self, iv, dub):
        mask = 0xF0
        dove = iv[0] & 0x07

        # Questo bit mi dice in quale nibble ...
        if iv[0] & self._BIT_POS_DUB:
            mask = 0x0F
            dub <<= 4

            # ... e dove prendere la posizione
            dove = iv[0] & 0x70
            dove >>= 4

        # I bit 0/2 mi dicono in quale posizione ...
        pos = iv[dove] & 0x07
        # ... a partire dal centro
        pos += 8

        iv[pos] = (iv[pos] & mask) | dub

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

    def crypt(self, cosa):
        """
        receives plaintext and returns the ciphertext

        :param cosa: bytearray/str
        :return: bytearray or None
        """
        if isinstance(cosa, str):
            cosa = bytes(cosa.encode('ascii'))

        # an handful of random bytes
        iv = bytearray(secrets.token_bytes(16))
        # troppi zeri
        # iv = bytearray([0] * 16)
        # fallisce dalla seconda volta (stesso v)
        # iv = bytearray([0] * 8)+bytearray([255] * 8)
        # fallisce dalla terza volta (alternanza)
        # global giv, giv1, giv2
        # iv = None
        # if giv is None:
        #     giv1 = bytearray(secrets.token_bytes(16))
        #     giv2 = bytearray(secrets.token_bytes(16))
        #     giv = giv1
        # if giv is giv1:
        #     iv = giv2
        #     giv = giv2
        # else:
        #     iv = giv1
        #     giv = giv1
        # print('IV = ' + utili.esa_da_ba(iv, ' '))

        # compute and save last block length
        dub = len(cosa) & 0x0F
        self._salva_dub(iv, dub)

        iv = bytes(iv)

        # ciphertext starts with iv
        out = bytearray(iv)

        # AES key
        key = self.hash(iv)

        # cipher it
        if dub:
            cosa = cosa + bytes([0] * (16 - dub))
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend())
        encryptor = cipher.encryptor()
        cosac = encryptor.update(bytes(cosa)) + encryptor.finalize()
        out += cosac

        # sign it
        key = self.hash(key)

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        digest.update(cosac)
        out += digest.finalize()

        return out

    def decrypt(self, cosa):
        """
        receives ciphertext and returns the plaintext

        :param cosa: bytearray
        :return: bytearray or None
        """
        # break it
        iv = bytes(cosa[:16])
        dim = len(cosa)
        firma = cosa[dim - 32:]
        cri = bytes(cosa[16:dim - 32])

        # last block length
        dub = self._leggi_dub(iv)

        # AES key
        key = self.hash(iv)

        # decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend())
        decryptor = cipher.decryptor()
        pia = decryptor.update(cri) + decryptor.finalize()

        # Compute sign
        key = self.hash(key)

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key)
        digest.update(cri)
        firma_calc = digest.finalize()

        if firma == firma_calc:
            dim = len(pia)
            if dub:
                dim -= 16
                dim += dub

            return pia[:dim]

        return None

class CYBLE_AESCCM:
    """
    To be used with cyble internal functions
    """

    def __init__(self, key16):
        self.aesccm = AESCCM(key16, tag_length=4)

    def CyBle_AesCcmEncrypt(self, nonce13, plaintext):
        """
        Acts like the cyble function

        :param nonce13: bytes
        :param plaintext: bytes (1..27)
        :return: ciphertext (bytes)
        """
        return self.aesccm.encrypt(nonce13, plaintext, bytes([1]))

    def CyBle_AesCcmDecrypt(self, nonce13, ciphertext):
        """
        Acts like the cyble function

        :param nonce13: bytes
        :param ciphertext: bytes (1..27)
        :return: plaintext (bytes)
        """
        return self.aesccm.decrypt(nonce13, ciphertext, bytes([1]))

    def crypt(self, cosa):
        """
        receives plaintext and returns the ciphertext

        :param cosa: bytes/str
        :return: bytes
        """
        if isinstance(cosa, str):
            cosa = bytes(cosa.encode('ascii'))

        # an handful of random bytes
        ahorb = bytes(secrets.token_bytes(13))

        return ahorb + self.CyBle_AesCcmEncrypt(ahorb, cosa)

    def decrypt(self, cosa):
        """
        receives ciphertext and returns the plaintext

        :param cosa: bytes
        :return: bytes
        """

        return self.CyBle_AesCcmDecrypt(bytes(cosa[:13]), bytes(cosa[13:]))


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

    # sempre robe diverse
    sicurezza = PRIVACY(un_segreto)
    testo = 'ciao'
    for _ in range(10):
        ct = sicurezza.crypt(testo)
        utili.StampaEsa(ct, 'ct: ')

        pt = sicurezza.decrypt(ct)
        x = str(pt.decode('ascii'))
        print(testo == x)

    # giusto giusto
    testo = '123456789ABCDEF0'
    ct = sicurezza.crypt(testo)
    utili.StampaEsa(ct, 'ct: ')

    pt = sicurezza.decrypt(ct)
    x = str(pt.decode('ascii'))
    print(testo == x)

    # grande
    testo = '4aiQJ105gFviPSFHewO59ddjeAdO2osXSTw7BSFu'
    ct = sicurezza.crypt(testo)
    utili.StampaEsa(ct, 'ct: ')

    pt = sicurezza.decrypt(ct)
    x = str(pt.decode('ascii'))
    print(testo == x)

    # crono = utili.CRONOMETRO()
    # quante = 1000
    # crono.conta()
    # for _ in range(quante):
    #     ct = sicurezza.cifra(testo)
    #     pt = sicurezza.decifra(ct)
    # durata = crono.durata()
    # durata *= 1000.0
    # print('{} giri completi in '.format(quante) + utili.stampaDurata(durata))
    # una = durata / (quante * 2.0)
    # print('uno in {:.3f} ms'.format(una))
