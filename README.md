# RSA

Example RSA using OpenSSL BN multiprecision structure.

Include this header file in main and call it. 

Algorithm using BN:

p and q s.t. p != q

n = pxq

p_1 = p - 1
q_1 = q - 1

euler's totient function = p_1 x q_1

find public exponent e relatively prime to totient, or s.t. gcd(e, totient) = 1

find private exponent d, the multiplicative inverse of e.

encrypt: ciphertext = (plaintext)^d mod n using public exponent

decrypt: plaintexrt = ciphertext^e mod n.

simple signature: c^e mod n.





