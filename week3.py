from Crypto.Hash import SHA256


def get_file_hash(path: str) -> str:
    f = open(path, "rb")
    blocks = []
    try:
        while 1:
            block = f.read(1024)
            if block == b'':
                break
            blocks.append(block)
    finally:
        f.close()

    blocks.reverse()

    h = SHA256.new(blocks[0])
    for block in blocks[1:]:
        block += h.digest()
        h = SHA256.new(block)

    return h.hexdigest()


if __name__ == "__main__":
    # test file
    hash1 = get_file_hash('week3_files/test1.mp4')
    print(hash1)
    assert hash1 == '03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8'

    # assignment question file
    print(get_file_hash('week3_files/question.mp4'))
