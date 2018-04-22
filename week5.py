def xgcd(a, b):
    """xgcd(a,b) returns a tuple of form (g,x,y), where g is gcd(a,b) and
    x,y satisfy the equation g = ax + by."""
    a1 = 1
    b1 = 0
    a2 = 0
    b2 = 1
    aneg = 1
    bneg = 1
    if a < 0:
        a = -a
        aneg = -1
    if b < 0:
        b = -b
        bneg = -1
    while 1:
        quot = -(a // b)
        a = a % b
        a1 = a1 + quot * a2
        b1 = b1 + quot * b2
        if a == 0:
            return b, a2 * aneg, b2 * bneg
        quot = -(b // a)
        b = b % a;
        a2 = a2 + quot * a1
        b2 = b2 + quot * b1
        if b == 0:
            return a, a1 * aneg, b1 * bneg


def inverse_mod(a, n):
    """inverse_mod(b,n) - Compute 1/b mod n."""
    (g, xa, xb) = xgcd(a, n)
    if g != 1: raise ValueError(
        "***** Error *****: {0} has no inverse (mod {1}) as their gcd is {2}, not 1.".format(a, n, g))
    return xa % n


def dlog(g, h, p):
    # build h/g^x1 hash table
    hash_table = {}
    B = pow(2, 20, p)
    for x1 in range(0, B):
        val = (h * inverse_mod(pow(g, x1, p), p)) % p
        hash_table[val] = x1

    # count (g^B)^x0 and try to find match in hash_table
    # return as answer if found
    for x0 in range(0, B):
        val = pow(pow(g, B, p), x0, p)
        if val in hash_table:
            res_x0 = x0
            res_x1 = hash_table[val]
            return (res_x0 * B + res_x1) % p

    raise ValueError("logd could not be found")


if __name__ == "__main__":
    p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
    g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
    h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333

    x = dlog(g, h, p)
    print(x)
    assert pow(g, x, p) == h % p
