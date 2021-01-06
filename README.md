# py_DDFE
Python implementation of Dynamic Decentralized Functional Encryption

- original paper: [Dynamic Decentralized Functional Encryption](https://eprint.iacr.org/2020/197)

# Dependencies

- [py_ecc](https://github.com/ethereum/py_ecc)

# Functions
## All-or-Nothing Encapsulation(AoNE)
- function f(x) = (pk,x)

## Decentralized Sum (DSum)
- function f(x) = x_0 + x_1 + ... + x_n

## Inner-Product DDFE (IP-DDFE)
- function f(keys, x) = x_0 * y_0 + ... + x_n * y_n