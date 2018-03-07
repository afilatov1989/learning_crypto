from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def cbc_encrypt(plain: list, key: list) -> list:
    cipher = plain
    return cipher


def cbc_decrypt(cipher: list, key: list) -> list:
    plain = cipher
    return plain


def ctr_encrypt(plain: list, key: list) -> list:
    cipher = plain
    return cipher


def ctr_decrypt(cipher: list, key: list) -> list:
    plain = cipher
    return plain


def unhexify_string(line):
    return [int(line[i:i + 2], 16) for i in range(0, len(line), 2)]


def hexlist_to_string(list):
    return ''.join([chr(ch) for ch in list])


if __name__ == "__main__":
    cbc_key = unhexify_string('140b41b22a29beb4061bda66b6747e14')
    cbc_ct1 = unhexify_string(
        '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')

    pt = cbc_decrypt(cbc_ct1, cbc_key)
    print('cbc_pt1:')
    print(hexlist_to_string(pt))
    assert cbc_encrypt(pt, cbc_key) == cbc_ct1

    cbc_ct2 = unhexify_string(
        '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')

    pt = cbc_decrypt(cbc_ct2, cbc_key)
    print('cbc_pt2:')
    print(hexlist_to_string(pt))
    assert cbc_encrypt(pt, cbc_key) == cbc_ct2

    ctr_key = unhexify_string('36f18357be4dbd77f050515c73fcf9f2')
    ctr_ct1 = unhexify_string(
        '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')

    pt = ctr_decrypt(ctr_ct1, ctr_key)
    print('ctr_pt1:')
    print(hexlist_to_string(pt))
    assert ctr_encrypt(pt, cbc_key) == ctr_ct1

    ctr_ct2 = unhexify_string(
        '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')

    pt = ctr_decrypt(ctr_ct2, ctr_key)
    print('ctr_pt2:')
    print(hexlist_to_string(pt))
    assert ctr_encrypt(pt, cbc_key) == ctr_ct2
