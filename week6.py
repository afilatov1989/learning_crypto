from decimal import *


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
        b = b % a
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


def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def challenge1():
    print("CHALLENGE 1")
    N = 179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581
    print("N = " + str(N))
    A = isqrt(N) + 1
    x = isqrt(A * A - N)
    p = A - x
    q = A + x
    assert (p * q == N)
    print("p = " + str(p))
    print("q = " + str(q))


def challenge2():
    print("CHALLENGE 2")
    N = 648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877
    print("N = " + str(N))
    A = isqrt(N)
    while True:
        x = isqrt(A * A - N)
        p = A - x
        q = A + x
        if p * q == N:
            print("p = " + str(p))
            print("q = " + str(q))
            return
        A += 1


def challenge3():
    print("CHALLENGE 3")
    N = 720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929
    print("N = " + str(N))
    getcontext().prec = 350
    A = Decimal(isqrt(6 * N)) + Decimal(0.5)
    while True:
        x = Decimal(A * A - 6 * Decimal(N)).sqrt()
        p = int(A - x)
        q = int(A + x)
        if (p * q) == (6 * N):
            if p % 3 == 0 and q % 2 == 0:
                p //= 3
                q //= 2
                break
            if p % 2 == 0 and q % 3 == 0:
                p //= 2
                q //= 3
                break
        A += 1

    print("p = " + str(p))
    print("q = " + str(q))


def challenge4():
    print("CHALLENGE 4")
    ct = 22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540
    p = 13407807929942597099574024998205846127479365820592393377723561443721764030073662768891111614362326998675040546094339320838419523375986027530441562135724301
    q = 13407807929942597099574024998205846127479365820592393377723561443721764030073778560980348930557750569660049234002192590823085163940025485114449475265364281
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)

    pt = pow(ct, d, p * q)
    res = bytes.fromhex(hex(pt).split('00')[1])

    print(res)


if __name__ == "__main__":
    challenge1()
    challenge2()
    challenge3()
    challenge4()
