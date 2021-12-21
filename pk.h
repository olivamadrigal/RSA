#include <openssl/bn.h> //BN multiprecision strucuts....
#include <openssl/rsa.h>
#include <limits.h>
#include <stdio.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <assert.h>
#include <openssl/rand.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

// ref: https://linux.die.net/man/3/bn_cmp
// http://cse.sustech.edu.cn/faculty/~zhangfw/20fa-cs315/labs/lab10-instruction-public-key.pdf
void rsa_bn_version(void)
{
    BIGNUM *p, *q, *p_1, *q_1, *n, *e, *gcd, *d, *one, *totient, *CT, *PT, *ssk;
    BN_CTX *ctx;
    int secret = 99;
    int tries, test;
    
    ctx = BN_CTX_new();//holds bn temp vars
    p = BN_new();
    q = BN_new();
    p_1 = BN_new();
    q_1 = BN_new();
    n = BN_new();
    one = BN_new();
    totient = BN_new();
    gcd = BN_new();
    e = BN_new();
    d = BN_new();
    CT = BN_new();
    ssk = BN_new();
    PT = BN_new();
    
    //4 bit random primes
    BN_generate_prime_ex(p, 10, 1, NULL, NULL, NULL);
    do{
        BN_generate_prime_ex(q, 10, 1, NULL, NULL, NULL);
    }while(BN_cmp(p,q) == 0);
    
    printf("p = %s\n", BN_bn2dec(p));
    printf("q = %s\n", BN_bn2dec(q));

    BN_mul(n, p, q, ctx); // compute the modulus n=pxq
    printf("n = %s\n", BN_bn2dec(n));

    BN_set_word(one, 1);
    printf("1 = %s\n", BN_bn2dec(one));

    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);
    BN_mul(totient, p_1, q_1, ctx); // compute euler totient function phi(n)=(p-1)(q-1) at 6 bits
    printf("totient = %s\n", BN_bn2dec(totient));
    printf("p_1 = %s\n", BN_bn2dec(p_1));
    printf("q_1 = %s\n", BN_bn2dec(q_1));

    tries = 0;
    do
    {
        //generate public key e that is relatively prime to totient or s.t. gcd(e,totient) = 1
        BN_generate_prime_ex(e, 9, 1, NULL, NULL, NULL);
        BN_gcd(gcd, e, totient, ctx);
        tries++;
        
    }while(BN_is_one(gcd) != 1);
    
    printf("Tries to get e: %d\n", tries);
    printf("e = %s\n", BN_bn2dec(e));

    //now find the private key or multiplicative inverse of e mod totient => d*e is congruent to 1 mod totient
    BN_mod_inverse(d, e, totient, ctx);
    printf("d = %s\n", BN_bn2dec(d));
    
    //great... now I can ecryopt or sign
    //ENCRYPT
    BN_set_word(ssk, secret);
    BN_mod_exp(CT, ssk, e, n, ctx);
    printf("ssk %s\n", BN_bn2dec(ssk));
    printf("CT %s\n", BN_bn2dec(CT));
    
    //DECRYPT
    BN_mod_exp(PT, CT, d, n, ctx);
    printf("PT %s\n", BN_bn2dec(PT));
    
    test = (int)strtol(BN_bn2dec(PT), (char**)NULL, 10);
    assert(secret == test);
    
    BN_free(p);
    BN_free(q);
    BN_free(p_1);
    BN_free(q_1);
    BN_free(n);
    BN_free(e);
    BN_free(gcd);
    BN_free(d);
    BN_free(one);
    BN_free(totient);
    BN_free(CT);
    BN_free(PT);
    BN_free(ssk);
    
}

/*
EXAMPLE RUN:

p = 983
q = 1019
n = 1001677
1 = 1
totient = 999676
p_1 = 982
q_1 = 1018
Tries to get e: 1
e = 467

test on wolfram alpha:
gcd(467,999676) = 1
https://www.wolframalpha.com/input/?i=gcd%28467%2C999676%29

d = 847691
test: e*d is congruent to 1 mod totient
395871697 mod 999676 = 1
https://www.wolframalpha.com/input/?i=395871697+mod+999676

so we can see d is the multiplicative inverse of e mod totient.
ssk 99

CT 851698
TEST: shared scret key ssk^(e) mod n == CT....
https://www.wolframalpha.com/input/?i=%2899%5E467%29mod1001677

PT 99 we got it ... :)
*/
