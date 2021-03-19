# Details:
As the challenge name implies, this problem has to do with the given implementation of Elliptic Curve Digital Signature Algorithm (ECDSA).

## Write up:

So we are given a script :

```py
import ecdsa
import random
from Crypto.Cipher import AES
import binascii

def pad(m):
    return m+chr(16-len(m)%16)*(16-len(m)%16)

gen = ecdsa.NIST256p.generator
order = gen.order()
secret = random.randrange(1,order)
 
pub_key = ecdsa.ecdsa.Public_key(gen, gen * secret)
priv_key = ecdsa.ecdsa.Private_key(pub_key, secret)
 
nonce1 = random.randrange(1, 2**127)
nonce2 = nonce1
 
# randomly generate hash value
hash1 = random.randrange(1, order)
hash2 = random.randrange(1, order)
 
sig1 = priv_key.sign(hash1, nonce1)
sig2 = priv_key.sign(hash2, nonce2)

s1 = sig1.s
s2 = sig2.s

print("r: " + str(sig1.r))
print("s1: " + str(s1))
print("s2: " + str(s2))
print("")
print("hashes:")
print(hash1)
print(hash2)
print("")
print("order: " + str(order))
print("")

aes_key = secret.to_bytes(64, byteorder='little')[0:16]

ptxt =  pad("flag{example}")
IV = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
cipher = AES.new(aes_key, AES.MODE_CBC, IV)
ctxt = cipher.encrypt(ptxt.encode('utf-8'))

print("Encrypted Flag:")
print(binascii.hexlify(ctxt))
```


And the output from the script was:

```py
r: 50394691958404671760038142322836584427075094292966481588111912351250929073849
s1: 26685296872928422980209331126861228951100823826633336689685109679472227918891
s2: 40762052781056121604891649645502377037837029273276315084687606790921202237960

hashes:
777971358777664237997807487843929900983351335441289679035928005996851307115
91840683637030200077344423945857298017410109326488651848157059631440788354195

order: 115792089210356248762697446949407573529996955224135760342422259061068512044369

Encrypted Flag:
b'f3ccfd5877ec7eb886d5f9372e97224c43f4412ca8eaeb567f9b20dd5e0aabd5'
```

After searching i found that we can recover private key using same k value.

I came up with following script to get key:
```py
from ecdsa import SigningKey, NIST224p
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.numbertheory import inverse_mod
from hashlib import sha1

def attack(publicKeyOrderInteger, signaturePair1, signaturePair2, messageHash1, messageHash2): 
    r1 = 50394691958404671760038142322836584427075094292966481588111912351250929073849
    s1 = 26685296872928422980209331126861228951100823826633336689685109679472227918891
    r2 = 50394691958404671760038142322836584427075094292966481588111912351250929073849
    s2 = 40762052781056121604891649645502377037837029273276315084687606790921202237960

    #Convert Hex into Int
    L1 = int(777971358777664237997807487843929900983351335441289679035928005996851307115, 16)
    L2 = int(91840683637030200077344423945857298017410109326488651848157059631440788354195, 16)

    if (r1 != r2):
        print("ERROR: The signature pairs given are not susceptible to this attack")
        return None

    #A bit of Math 
    #L1 = Hash(message_1) 
    #L2 = Hash(message_2)
    #pk = Private Key (unknown to attacker)
    #R  = r1 == r2
    #K  = K value that was used (unknown to attacker)
    #N  = integer order of G (part of public key)
    
    #         From Signing Defintion
    #s1 = (L1 + pk * R) / K Mod N    and     s2 = (L2 + pk * R) / K Mod N
    
    #         Rearrange 
    #K = (L1 + pk * R) / s1 Mod N    and     K = (L2 + pk * R) / s2 Mod N
    
    #         Set Equal
    #(L1 + pk * R) / s1 = (L2 + pk * R) / s2     Mod N
    
    #         Solve for pk (private key)
    #pk Mod N = (s2 * L1 - s1 * L2) / R * (s1 - s2)
    #pk Mod N = (s2 * L1 - s1 * L2) * (R * (s1 - s2)) ** -1

    numerator = (((s2 * L1) % publicKeyOrderInteger) - ((s1 * L2) % publicKeyOrderInteger))
    denominator = inverse_mod(r1 * ((s1 - s2) % publicKeyOrderInteger), publicKeyOrderInteger)

    privateKey = numerator * denominator % publicKeyOrderInteger

    return privateKey

if __name__ == "__main__":
    ### PROOF OF CONCEPT ####

    #Messages to be signed
    message_1 = str("777971358777664237997807487843929900983351335441289679035928005996851307115")
    message_2 = str("91840683637030200077344423945857298017410109326488651848157059631440788354195")

    #Generates the private key using the NIST224p curve, and SHA-1 hash function
    sk = SigningKey.generate(curve=NIST224p)

    #This is the secret number used to sign messages
    actualPrivateKey = sk.privkey.secret_multiplier

    #gets the public key (vk) 
    vk = sk.get_verifying_key()

    #Signing a message 
    signature = sk.sign(message_1.encode('utf-8'),k=22)

    #Pulling out the Signature Pair
    r1, s1 = sigdecode_string(signature, vk.pubkey.order)
    
    #Singing a second message using the same K value, using the same K value is what opens ECDSA to attack 
    signature2 = sk.sign(message_2.encode("utf-8"),k=22)

    #Pulling out the second Signature Pair (Note: r1 == r2 due to the K value being the same)
    r2, s2 = sigdecode_string(signature2, vk.pubkey.order)

    #Get message Hash 
    messageHash1 = sha1(message_1.encode('utf-8')).hexdigest()
    messageHash2 = sha1(message_2.encode('utf-8')).hexdigest()

    #Start the attack
    privateKeyCalculation = attack(vk.pubkey.order, (r1,s1), (r2,s2), messageHash1, messageHash2)
    
    #By compairing the actual secret key with calculation we can prove that we have just solved for the private key
    print(actualPrivateKey)
    print(privateKeyCalculation)
```
     

    After this we just need to decrypt AES CBC mode, so I came up with following script:
    
```py
    import sys
import base64
from Crypto.Cipher import AES

private_key=26924620604793025490002124762205825722410676804960639851404176074662508843402
encrypted_flag = 'f3ccfd5877ec7eb886d5f9372e97224c43f4412ca8eaeb567f9b20dd5e0aabd5'
aes_key = int(private_key).to_bytes(64, byteorder='little')[0:16]
IV = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

cipher = AES.new(aes_key, AES.MODE_CBC, IV)
print(cipher.decrypt(bytes.fromhex(encrypted_flag)).decode())
```
And after this decoding we finnaly got the flag which is:

```flag{cRypt0_c4r3fully}```