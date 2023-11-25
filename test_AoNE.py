from py_ecc import (
    optimized_bn128 as bn128,
)
import AoNE
import random

def test_main():
    userNum = 5
    pk = []
    sk = []
    r = [random.randint(0, bn128.field_modulus) for i in range(userNum)]
    x = [random.randint(0, bn128.field_modulus) for i in range(userNum)]
    K_pk = []
    r_pk_2 = []
    S_pk = []
    
    # Key generation
    for i in range(userNum):
        tmpPk, tmpSk = AoNE.KeyGen()
        pk.append(tmpPk)
        sk.append(tmpSk)

    # All users encrypt data
    for i in range(userNum):
        K, r2, S, l = AoNE.Encrypt(sk[i], x[i], r[i], pk[:i]+pk[i+1:] , 12345)
        K_pk.append(K)
        r_pk_2.append(r2)
        S_pk.append(S)
    
    # Decrypt each ciphertext
    for i in range(userNum):
        assert(AoNE.Decrypt(r[i],S_pk[:i]+S_pk[i+1:]) == K_pk[i])
    
    print("Test Finish!")