'''
Paper: "Dynamic Decentralized Functional Encryption" (https://eprint.iacr.org/2020/197)
Function: Rate-1 All-or-Nothing Encapsulation(AoNE)
'''
from py_ecc import (
    optimized_bn128 as bn128,
)
from py_ecc.fields.field_properties import (
    field_properties,
)
import random

# Key Generation
# KeyGen() -> (pk,sk_pk)
def KeyGen():
    t = random.randint(0,bn128.field_modulus)
    return (bn128.multiply(bn128.G2, t), t)

# Encryption
# Encryp(sk_pk, m) -> ct_pk
# ct_pk = (c_pk, [r_pk]_2, S_{pk, U_M, l}, U_M, l)
def Encrypt(sk, x, r, pk ,label):
    # compute symmetric key K
    h_1 = bn128.multiply(bn128.G1, label)
    sum_pk = pk[0]
    for i in range(1,len(pk)):
        sum_pk = bn128.add(sum_pk, pk[i])
    K = bn128.pairing(bn128.multiply(sum_pk, r),h_1)
    S = bn128.multiply(h_1, sk)
    
    # TODO: encrypt x with K
    return K, bn128.multiply(bn128.G2,r), S, label

# Decryption
# Decrypt(ct) -> x
def Decrypt(r, S):
    sum_pk = S[0]
    for i in range(1, len(S)):
        sum_pk = bn128.add(sum_pk, S[i])
    g2 = bn128.multiply(bn128.G2, r)
    K = bn128.pairing(g2, sum_pk)

    # TODO: decrypt ct with K
    return K


