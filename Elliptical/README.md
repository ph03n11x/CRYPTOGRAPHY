# Details:
This challenge was ECDSA, but with slight difference. K is not random, it is always the same.

## Write UP:

The main thing is that when you logged in as the same user the sigs were the same that's a big red flag that the k value is the same cause k should be generated ranodmly meanign the signature should be dfferent even if you login with the same person. So for example when I login as Abda I got k = 10,, but when I login as John I also get k = 10 , and it should be different every time we login. And the whole point is recovering r and s from the jwt signature.

So here is my script to solve it. I treid to write it in Python3 but I couldnt get some libraries to work, so I made following script in python2:

```py
import base64
from Crypto.Util.number import long_to_bytes, bytes_to_long
import hashlib
import gmpy2
from ecdsa import SigningKey, NIST256p
import ecdsa

#n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

n = int("FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551".replace(" ", ""), 16)
# secp256k1
#n = int("FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141".replace(" ", ""), 16)

o1 = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJhYWFhYWFhYWFhYWFhYWFhIn0.wN0kGlDUj5n8x6GGptROB2PskEeOHe-ONvXE6VDWevv96hqrSKtuHHX5lgr69UJedGwfEuOZFRKD1WL54xNm8g".split(".")
o2 = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICIxMjMifQ.wN0kGlDUj5n8x6GGptROB2PskEeOHe-ONvXE6VDWevvnac7aBS8XFXVw_bEK7T7le6SoXCmnyoccFQZncNkyVw".split(".")

sig1 = base64.urlsafe_b64decode(o1[2] + "==")
sig2 = base64.urlsafe_b64decode(o2[2] + "==")

r1 = bytes_to_long(sig1[:32])
s1 = bytes_to_long(sig1[32:])

r2 = bytes_to_long(sig2[:32])
s2 = bytes_to_long(sig2[32:])

z1 = bytes_to_long(hashlib.sha256(o1[0] + "." + o1[1]).digest())
z2 = bytes_to_long(hashlib.sha256(o2[0] + "." + o2[1]).digest())

sdiff_inv = gmpy2.invert(s2 - s1, n)
k = ( (z2 - z1) * sdiff_inv) % n

print("k = ", k)
secret_key = ((s1 * k - z1) * gmpy2.invert(r1, n)) % n
# Now that we got the secret key, we just re-encrypt it

G = ecdsa.NIST256p.generator
assert n == G.order()

sk = SigningKey.from_string(long_to_bytes(secret_key), curve=NIST256p, hashfunc=hashlib.sha256)
print(sk)
my_message = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9" + "." + "eyJ1c2VybmFtZSI6ICJhZG1pbiJ9"
signature = sk.sign(my_message, k=k)
print "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9" + "." + "eyJ1c2VybmFtZSI6ICJhZG1pbiJ9"s + "." + base64.urlsafe_b64encode(signature)

```

After this we get base64 encoded value. After that I came back to the website and change the value of cookie which gave me admin login and I got the flag.
