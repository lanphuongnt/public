# ELLIPTIC CURVES

## BACKGROUND

### Background Reading
Câu hỏi challenge này là: `Property (d) shows that point addition is commutative. The flag is the name we give groups with a commutative operation.`
https://en.wikipedia.org/wiki/Abelian_group#:~:text=In%20mathematics%2C%20an%20abelian%20group,the%20group%20operation%20is%20commutative.
Flag : `crypto{Abelian}`

## STARTER
### Point Negation
For all the challenges in the starter set, we will be working with the elliptic curve
> E: Y2 = X3 + 497 X + 1768, p: 9739
Using the above curve, and the point `P(8045,6936)`, find the point `Q(x,y)` such that `P + Q = O`.

Ta thấy `P + Q = O` hay  `Q = -P = (x, -y) = (8045, -6936 mod p) = (8045, 2803)` 

Vay `flag = crypto{8045,2803}`

### Point Addition

Algorithm for the addition of two points: P + Q

(a) If P = O, then P + Q = Q.
(b) Otherwise, if Q = O, then P + Q = P.
(c) Otherwise, write P = (x1, y1) and Q = (x2, y2).
(d) If x1 = x2 and y1 = −y2, then P + Q = O.
(e) Otherwise:
  (e1) if P ≠ Q: λ = (y2 - y1) / (x2 - x1)
  (e2) if P = Q: λ = (3x12 + a) / 2y1
(f) x3 = λ2 − x1 − x2,     y3 = λ(x1 −x3) − y1
(g) P + Q = (x3, y3)

Using the above curve, and the points  `P = (493, 5564)`, `Q = (1539, 4742)`, `R = (4403,5202)`, find the point `S(x,y) = P + P + Q + R` by implementing the above algorithm.

```python
a = 497
b = 1768
p = 9739

def add(P, Q):
    if P[0] % p == P[1] % p == 0:
        return Q
    elif Q[0] % p == Q[1] % p == 0:
        return P
    else:
        (x1, y1) = P
        (x2, y2) = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return (0, 0)
        else:
            if P != Q:
                tem = (((y2 - y1) % p) * pow(x2 - x1, -1, p)) % p
            else:
                tem = (((3 * x1 * x1 + a) % p) * pow(2 * y1, -1, p)) % p
            x3 = (tem * tem - x1 - x2) % p 
            y3 = (tem * (x1 - x3) - y1) % p 
            return (x3, y3)
        
X = (5274, 2841)
Y = (8669, 740)

print(add(X, Y), add(X, Y) == (1024, 4440))
print(add(X, X), add(X, X) == (7284, 2107))

P = (493, 5564)
Q = (1539, 4742)
R = (4403,5202)

S = add(add(add(P, P), Q), R)
print(f"S(x,y) = P + P + Q + R = {S}")
print(f"Flag : crypto\x7b{S[0]},{S[1]}\x7d")

# Output:
# (1024, 4440) True
# (7284, 2107) True
# S(x,y) = P + P + Q + R = (4215, 2162)
# Flag : crypto{4215,2162}

```
### Scalar Multiplication

Double and Add algorithm for the scalar multiplication of point P by n

Input: P in E(Fp) and an integer n > 0
1. Set Q = P and R = O.
2. Loop while n > 0.
  3. If n ≡ 1 mod 2, set R = R + Q.
  4. Set Q = 2 Q and n = ⌊n/2⌋.
  5. If n > 0, continue with loop at Step 2.
6. Return the point R, which equals nP.


Using the above curve, and the points `P = (2339, 2213)`, find the point `Q(x,y) = 7863 P` by implementing the above algorithm.

After calculating `Q`, substitute the coordinates into the curve. Assert that the point `Q` is in `E(Fp)`.

```python
a = 497
b = 1768
p = 9739

def add(P, Q):
    if P[0] % p == P[1] % p == 0:
        return Q
    elif Q[0] % p == Q[1] % p == 0:
        return P
    else:
        (x1, y1) = P
        (x2, y2) = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return (0, 0)
        else:
            if P != Q:
                tem = (((y2 - y1) % p) * pow(x2 - x1, -1, p)) % p
            else:
                tem = (((3 * x1 * x1 + a) % p) * pow(2 * y1, -1, p)) % p
            x3 = (tem * tem - x1 - x2) % p 
            y3 = (tem * (x1 - x3) - y1) % p 
            return (x3, y3)

def scalar_multiplication(P, n):
    if n <= 0:
        return (-1, -1)
    Q = P
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n >>= 1
    return R

X = (5323, 5438)
print(scalar_multiplication(X, 1337), scalar_multiplication(X, 1337) == (1089, 6931))

P = (2339, 2213)
Q = scalar_multiplication(P, 7863)
print(f"Flag : crypto\x7b{Q[0]},{Q[1]}\x7d")

# (1089, 6931) True
# Flag : crypto{9467,2742}

```

###  Curves and Logs

Calculate the shared secret after Alice sends you QA = (815, 3190), with your secret integer nB = 1829.

Generate a key by calculating the SHA1 hash of the x coordinate (take the integer representation of the coordinate and cast it to a string). The flag is the hexdigest you find.

```python
import hashlib
from Crypto.Util.number import *
a = 497
b = 1768
p = 9739

def add(P, Q):
    if P[0] % p == P[1] % p == 0:
        return Q
    elif Q[0] % p == Q[1] % p == 0:
        return P
    else:
        (x1, y1) = P
        (x2, y2) = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return (0, 0)
        else:
            if P != Q:
                tem = (((y2 - y1) % p) * pow(x2 - x1, -1, p)) % p
            else:
                tem = (((3 * x1 * x1 + a) % p) * pow(2 * y1, -1, p)) % p
            x3 = (tem * tem - x1 - x2) % p 
            y3 = (tem * (x1 - x3) - y1) % p 
            return (x3, y3)

def scalar_multiplication(P, n):
    if n <= 0:
        return (-1, -1)
    Q = P
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n >>= 1
    return R

Qa = (815, 3190)
nb = 1829
S = scalar_multiplication(Qa, nb)
x = str(S[0]).encode('utf-8')

hashx = hashlib.sha1(x).hexdigest()
print(f"crypto\x7b{hashx}\x7d")

# crypto{80e5212754a824d3a4aed185ace4f9cac0f908bf}
```

### Efficient Exchange

Calculate the shared secret after Alice sends you q_x = 4726, with your secret integer nB = 6534.

Use the decrypt.py file to decode the flag

{'iv': 'cd9da9f1c60925922377ea952afc212c', 'encrypted_flag': 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'}

```python
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

a = 497
b = 1768
p = 9739
G = (1804,5368)
q_x = 4726
nb = 6534

def add(P, Q):
    if P[0] % p == P[1] % p == 0:
        return Q
    elif Q[0] % p == Q[1] % p == 0:
        return P
    else:
        (x1, y1) = P
        (x2, y2) = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return (0, 0)
        else:
            if P != Q:
                tem = (((y2 - y1) % p) * pow(x2 - x1, -1, p)) % p
            else:
                tem = (((3 * x1 * x1 + a) % p) * pow(2 * y1, -1, p)) % p
            x3 = (tem * tem - x1 - x2) % p 
            y3 = (tem * (x1 - x3) - y1) % p 
            return (x3, y3)

def scalar_multiplication(P, n):
    if n <= 0:
        return (-1, -1)
    Q = P
    R = (0, 0)
    while n > 0:
        if n % 2 == 1:
            R = add(R, Q)
        Q = add(Q, Q)
        n >>= 1
    return R


def find_y(x):
    y2 = (x**3 + a * x + b) % p
    # y^2 = y2 mod p => y = y2^((p + 1)/4) because p = 3 mod 4
    return pow(y2, (p + 1)//4, p)
        
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


q_y = find_y(q_x)
Qa = (q_x, q_y)
(x, _) = scalar_multiplication(Qa, nb)


mes = {'iv': 'cd9da9f1c60925922377ea952afc212c', 'encrypted_flag': 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'}

shared_secret = x
iv = mes['iv']
ciphertext = mes['encrypted_flag']

print(decrypt_flag(shared_secret, iv, ciphertext))
        

# crypto{3ff1c1ent_k3y_3xch4ng3}

```

## PARAMETER CHOICE

### Smooth Criminal
Trong bài này ta biết được điểm Qa và G và Qa = nA.G, ta cần tìm nA để tìm ra shared_secret.
Check thử E.order() thì ta thấy E.order() là một smooth number. Vì vậy, trong bài này đường cong Ellip là 1 đường cong yếu.
Mình áp dụng thuật toán Pohlig-Hellman để tìm ra nA.

```python
from Crypto.Cipher import AES
from Crypto.Util.number import inverse
from Crypto.Util.Padding import pad, unpad
from collections import namedtuple
from random import randint
import hashlib
import os
from sage.all import *

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# The point at infinity (origin for the group law).
O = 'Origin'

def check_point(P: tuple):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p


def point_inverse(P: tuple):
    if P == O:
        return P
    return Point(P.x, -P.y % p)


def point_addition(P: tuple, Q: tuple):
    # based of algo. in ICM
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            lam = (3*P.x**2 + a)*inverse(2*P.y, p)
            lam %= p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % p
    Ry = (lam*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert check_point(R)
    return R


def double_and_add(P: tuple, n: int):
    # based of algo. in ICM
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q)
        Q = point_addition(Q, Q)
        n = n // 2
    assert check_point(R)
    return R


def gen_shared_secret(Q: tuple, n: int):
    # Bob's Public key, my secret int
    S = double_and_add(Q, n)
    return S.x


def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


p = 310717010502520989590157367261876774703
a = 2
b = 3

E = EllipticCurve(GF(p), [a, b])

g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = E.point((g_x, g_y))

Qa = E.point((280810182131414898730378982766101210916, 291506490768054478159835604632710368904))

primes = []
for i in factor(Qa.order()):
    primes.append(i[0]**i[1])

dlogs = []
for i in primes:
    t = int(G.order() / i)
    dlog = discrete_log(t*Qa, t*G, operation = '+')
    dlogs.append(dlog)

nA = CRT_list(dlogs, primes)

# Bob's public key
b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = Point(b_x, b_y)                 # QB


enc = "8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af"
iv = "07e2628b590095a5e332d397b8a59aa7"
# Calculate Shared Secret
shared_secret = gen_shared_secret(B, nA)     # S = nA.QB[x]

# Send this to Bob!
flag = decrypt_flag(shared_secret, iv, enc)
print(flag)


# Output:
# crypto{n07_4ll_curv3s_4r3_s4f3_curv3s}
```
