"""
Paper: "Dynamic Decentralized Functional Encryption" (https://eprint.iacr.org/2020/197)
Function: Rate-1 All-or-Nothing Encapsulation(AoNE)
"""
import random
from py_ecc import (
    optimized_bn128 as bn128,
)


class AoNE:
    """AoNE class implementation"""

    # Key Generation
    # KeyGen() -> (pk,sk_pk)

    def keygen(self):
        """Generate a key pair"""
        t = random.randint(0, bn128.field_modulus)
        return (bn128.multiply(bn128.G2, t), t)

    def encrypt(self, sk, r, pk, label):
        """
        Encryption
        Encrypt(sk_pk, m) -> ct_pk
        ct_pk = (c_pk, [r_pk]_2, S_{pk, U_M, l}, U_M, l)
        """
        # compute symmetric key K
        h_1 = bn128.multiply(bn128.G1, label)
        sum_pk = pk[0]
        for i in range(1, len(pk)):
            sum_pk = bn128.add(sum_pk, pk[i])
        k = bn128.pairing(bn128.multiply(sum_pk, r), h_1)
        s = bn128.multiply(h_1, sk)

        # TODO: encrypt x with k
        return k, bn128.multiply(bn128.G2, r), s, label

    def decrypt(self, r, s):
        """
        Decryption
        Decrypt(ct) -> x
        """
        sum_pk = s[0]
        for i in range(1, len(s)):
            sum_pk = bn128.add(sum_pk, s[i])
        g2 = bn128.multiply(bn128.G2, r)
        k = bn128.pairing(g2, sum_pk)

        # TODO: decrypt ct with k
        return k
