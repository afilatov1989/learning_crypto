import binascii
import urllib.request
import urllib.error

TARGET = 'http://crypto-class.appspot.com/po?er='


# --------------------------------------------------------------
# padding oracle
# --------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib.request.quote(q)  # Create query URL
        req = urllib.request.Request(target)  # Send HTTP request to server
        try:
            urllib.request.urlopen(req)  # Wait for response
        except urllib.request.HTTPError as e:
            if e.code == 404:
                return True  # good padding
            elif e.code == 403:
                return False  # bad padding
            else:
                print("Query: %s" % q)  # Print request
                raise ValueError("Incorrect response code: %d" % e.code)  # Print response code
        except urllib.error.URLError:
            return self.query(q)


def unhexify_string(line: str) -> bytes:
    return bytes([int(line[i:i + 2], 16) for i in range(0, len(line), 2)])


def decipher(line: bytes) -> bytes:
    po = PaddingOracle()
    res = b''
    for i in range(1, 17):
        match = False
        # Guessing strategy: check space, letters and only then generic chars
        for guess in [32] + list(range(97, 123)) + list(range(65, 91)) + list(range(0, 256)):
            changed_line = bytearray(line)
            changed_line[-16 - i] ^= i ^ guess
            for j in range(1, i):
                changed_line[-16 - j] ^= i ^ res[-j]
            if po.query(binascii.hexlify(bytes(changed_line))):
                match = True
                res = bytes([guess]) + res
                print(b'Deciphered: "' + res + b'"')
                break
        if not match:
            raise ValueError('No valid padding found')

    return res


if __name__ == "__main__":
    ciphertext = unhexify_string(
        'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
    )
    iv = ciphertext[0:16]
    c0 = ciphertext[16:32]
    c1 = ciphertext[32:48]
    c2 = ciphertext[48:]

    m2 = decipher(iv + c0 + c1 + c2)
    m1 = decipher(iv + c0 + c1)
    m0 = decipher(iv + c0)

    print(m0 + m1 + m2)
