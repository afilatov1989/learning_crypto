from Crypto.Cipher import AES
from Crypto import Random


def cbc_encrypt(plain: bytes, key: bytes, iv: bytes = Random.new().read(AES.block_size)) -> bytes:
    cipher = iv
    pad = 16 - (len(plain) % 16)
    plain += bytes([pad]) * pad

    prev_ciphered_block = iv
    i = 0
    while i < len(cipher):
        cur_block = plain[i:i + 16]
        cur_ciphered_block = aes_encrypt_block(bytes(a ^ b for (a, b) in zip(cur_block, prev_ciphered_block)), key)
        cipher += cur_ciphered_block
        prev_ciphered_block = cur_ciphered_block
        i += 16

    return cipher


def cbc_decrypt(cipher: bytes, key: bytes) -> bytes:
    iv = cipher[:16]
    i = 16
    prev_block = iv
    plain = b''
    while i < len(cipher):
        cur_block = cipher[i:i + 16]
        dec_cur_block = aes_decrypt_block(cur_block, key)
        plain += bytes(a ^ b for (a, b) in zip(dec_cur_block, prev_block))
        prev_block = cur_block
        i += 16

    pad = int(plain[-1])
    return plain[:(-1) * pad]


def ctr_encrypt(plain: bytes, key: bytes) -> bytes:
    cipher = plain
    return cipher


def ctr_decrypt(cipher: bytes, key: bytes) -> bytes:
    plain = cipher
    return plain


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    encryptor = AES.new(key, AES.MODE_ECB)
    return encryptor.encrypt(block)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    encryptor = AES.new(key, AES.MODE_ECB)
    return encryptor.decrypt(block)


def unhexify_string(line: str) -> bytes:
    return bytes([int(line[i:i + 2], 16) for i in range(0, len(line), 2)])


if __name__ == "__main__":
    cbc_key = unhexify_string('140b41b22a29beb4061bda66b6747e14')
    cbc_ct1 = unhexify_string(
        '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')

    pt = cbc_decrypt(cbc_ct1, cbc_key)
    print('cbc_pt1:')
    print(pt)

    # use the same IV as above for testing purposes
    assert cbc_encrypt(pt, cbc_key, cbc_ct1[:16]) == cbc_ct1

    cbc_ct2 = unhexify_string(
        '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')

    pt = cbc_decrypt(cbc_ct2, cbc_key)
    print('cbc_pt2:')
    print(pt)

    # use the same IV as above for testing purposes
    assert cbc_encrypt(pt, cbc_key, cbc_ct2[:16]) == cbc_ct2

    ctr_key = unhexify_string('36f18357be4dbd77f050515c73fcf9f2')
    ctr_ct1 = unhexify_string(
        '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')

    pt = ctr_decrypt(ctr_ct1, ctr_key)
    print('ctr_pt1:')
    print(pt)
    assert ctr_encrypt(pt, cbc_key) == ctr_ct1

    ctr_ct2 = unhexify_string(
        '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')

    pt = ctr_decrypt(ctr_ct2, ctr_key)
    print('ctr_pt2:')
    print(pt)
    assert ctr_encrypt(pt, cbc_key) == ctr_ct2
