"""
Paper: "Dynamic Decentralized Functional Encryption" (https://eprint.iacr.org/2020/197)
Function: Decentralized Sum (DSum)
"""
from py_ecc import (
    optimized_bn128 as bn128,
)
from aone import AoNE


def bn128_less_than(a, b):
    """
    Check if a < b
    """
    return a[0].coeffs[0] < b[0].coeffs[0]


class DSum:
    """
    DSum class implementation
    """
    # Setup
    # NIKE.pp = NIKE.Setup(1^lambda)
    # AoNE.pp = AoNE.Setup(1^lambda)
    # pp = (NIKE.pp, AoNE.pp)
    aone = AoNE()

    def keygen(self):
        """
        Key Generation
        AoNE.KeyGen(pp) -> (AoNE.pk,AoNE.sk_pk)
        NIKE.KeyGen(pp) -> (NIKE.pk,NIKE.sk_pk)
        sk = (NIKE.sk_pk, AoNE.sk_pk)
        pk = (NIKE.pk, AoNE.pk)
        """
        return self.aone.keygen()

    def encrypt(self, sk, r, x, pk, label):
        """
        Encryption
        Encrypt(sk_pk, m) -> ct_pk
        ct_pk = (AoNE.Encrypt(AoNE.sk_pk, (c_pk, U_M, l)), U_M, l)
        """
        user_pk = bn128.multiply(bn128.G2, sk)
        # a PRF family (FK)K that takes keys from the NIKE and messages from {0, 1}
        # r_{pk,pk',U_M,l} = F_{K_{pk,pk'}}(UM||l).
        c_pk = x
        # TODO: compute r_pk where \sum_{pk'} r = 0
        # compute c_pk = c_pk + r_pk
        return self.aone.encrypt(sk, r, c_pk, pk, label)

    def decrypt(self, r, s):
        """
        Decryption
        Decrypt((ct)_{pk in U_M}) -> sum_{pk in U_M} c_{pk}
        """
        return self.aone.decrypt(r, s)
