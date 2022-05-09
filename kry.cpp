/**
 * @file kry.cpp
 * @author Adam Švenk (xsvenk00@stud.fit.vutbr.cz)
 * @brief Implements RSA key generating and cracking
 * @version 1.0
 * @date 2022-04-29
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>

// Miiller Test
// Implementation is based on www.geeksforgeeks.org/primality-test-set-3-miller-rabin/ 
bool miillerTest(mpz_t d, mpz_t n) {
    mpz_t a, x, n_1, n_4, remainder, numerator;
    mpz_inits(a, x, n_1, n_4, remainder, numerator, NULL);

    //a = 2 + rand() % (n - 4)
    //rand()
    mpz_set_ui(numerator, rand());    
    //(n - 4)
    mpz_sub_ui(n_4, n, 4);
    //rand() % (n - 4)
    mpz_mod(remainder, numerator, n_4);
    //a = 2 + rand() % (n - 4)
    mpz_add_ui(a, remainder, 2);

    mpz_powm(x, a, d, n);

    //n-1
    mpz_sub_ui(n_1, n, 1);

    if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_1) == 0) {
        mpz_clears(a, x, n_1, n_4, remainder, numerator, NULL);
        return true;
    }

    mpz_t temp;
    mpz_init(temp);

    while (mpz_cmp(d, n_1) != 0) {
        //(x * x)
        mpz_mul(temp, x, x);

        //(x * x) % n
        mpz_mod(x, temp, n);

        //d *= 2
        mpz_mul_ui(d, d, 2);

        if (mpz_cmp_ui(x, 1) == 0) {
            mpz_clears(a, x, n_1, n_4, remainder, numerator, temp, NULL);
            return false;
        }

        if (mpz_cmp(x, n_1) == 0) {
            mpz_clears(a, x, n_1, n_4, remainder, numerator, temp, NULL);
            return true;
        }
    }

    mpz_clears(a, x, n_1, n_4, remainder, numerator, temp, NULL);
    return false;
}

// Prime number test
// Implementation is based on www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
bool isPrime(mpz_t number) {
    mpz_t remainder, d;
    // Check edge cases
    if (mpz_cmp_ui (number, 1) < 0 || mpz_cmp_ui (number, 1) == 0) {
        return false;
    }

    if (mpz_cmp_ui (number, 4) == 0) {
        return false;
    }

    if (mpz_cmp_ui (number, 3) < 0 || mpz_cmp_ui (number, 3) == 0) {
        return true;
    }

    mpz_init(remainder);

    // Check if number is divisible by 2 without any remainder
    if (mpz_mod_ui(remainder, number, 2) == 0) {
        mpz_clear(remainder);
        return false;
    }

    mpz_init_set(d, number);
    mpz_sub_ui(d, d, 1);

    while (mpz_mod_ui(remainder, d, 2) == 0) {
        mpz_tdiv_q_ui(d, d, 2);
    }

    for (int i = 0; i < 128; i++) {
        if (!miillerTest(d, number)) {
            mpz_clears(remainder, d, NULL);
            return false;
        }
    }

    mpz_clears(remainder, d, NULL);
    return true;
}

// Encrypt the message
void encryptMessage(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    mpz_powm(c, m, e, n);
}

// Decrypt the message
void decryptMessage(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    mpz_powm(m, c, d, n);
}

// Calculate GCD
void gcd(mpz_t a, mpz_t b, mpz_t r) {
    mpz_t A, B, t;
    
    mpz_init(t);
    mpz_init_set(A, a);
    mpz_init_set(B, b);  
    
    while (mpz_cmp_ui(B, 0) != 0) {
        mpz_set(t, B);
        mpz_mod(B, A, B);
        mpz_set(A, t);
    }

    mpz_set(r, A);
    mpz_clears(A, B, t, NULL);
}

// Fermat’s Factorization Method
// Source: https://math4u.wordpress.com/2009/03/10/fermats-factorization-method-implemented-in-c-with-gmp/
void fermatsFactorization (mpz_t n, mpz_t p, mpz_t q) {
    mpz_t a, As, b, Bsq, Bsho, bs;
    mpz_inits(a, Bsq, Bsho, As, NULL);

    mpz_init_set_ui(bs, 1);
    mpz_init_set_ui(b, 2);

    mpz_sqrt(a, n);

    while (mpz_cmp(bs, b) != 0){
        mpz_add_ui(a, a, 1);
        mpz_pow_ui(As, a, 2);
        mpz_sub(b, As, n);
        mpz_sqrt(Bsq, b);
        mpz_pow_ui(bs, Bsq, 2);
    }

    mpz_sqrt(Bsq, b);
    mpz_sub(Bsho, a, Bsq);
    mpz_divexact(As, n, Bsho); 
    mpz_set(p, Bsho);
    mpz_set(q, As);
    mpz_clears(a, As, b, Bsq, Bsho, bs, NULL);
}

// Function used in Multiplicative Inverse
// Check J. Nechvatal - Public-Key Cryptography (NIST SP 800-2) for more information
void mIUpdate(mpz_t a, mpz_t b, mpz_t y) {
    mpz_t temp;
    
    mpz_init_set(temp, b);
    mpz_mul(temp, temp, y);
    mpz_sub(b, a, temp);
    mpz_divexact(temp, temp, y);
    mpz_set(a, temp);
    mpz_clear(temp);
}

// Calculate Multiplicative Inverse
// Implementation is based on J. Nechvatal - Public-Key Cryptography (NIST SP 800-2)
void multiplicativeInverse(mpz_t n, mpz_t x, mpz_t d) {
    mpz_t g, h, w, z, v, r, y;
    mpz_init_set(g, n);
    mpz_init_set(h, x);
    mpz_init_set_ui(w, 1);
    mpz_init_set_ui(z, 0);
    mpz_init_set_ui(v, 0);
    mpz_init_set_ui(r, 1);
    mpz_init(y);

    while (mpz_cmp_ui(h, 0) > 0) {
        mpz_tdiv_q(y, g, h);
        mIUpdate(g, h, y);
        mIUpdate(w, z, y);
        mIUpdate(v, r, y);
    }
    
    mpz_mod(d, v, n);

    mpz_clears(g, h, w, z, v, r, y, NULL);
}

// Generate random prime number which will have '1' on the MSB position
void getRandomPrimeBites(mpz_t n, gmp_randstate_t randState, int bites) {
    int msbIndex = bites - 1;
    
    do {
        mpz_urandomb(n, randState, bites);
        mpz_setbit(n, msbIndex);
    } while (isPrime(n) == false);
}

// Main program body
int main (int argc, char *argv[]) {
    // If number of arguments if wrong, exit program
    if (argc < 2 || argc > 5) {
        fprintf(stderr, "Error: Wrong program arguments\n");
        return 1;
    }

    // Save first program argument (besides program name)
    char *prog_arg = argv[1];

    // Generate RSA keys
    if (strcmp(prog_arg, "-g") == 0) {
        // Check number of the program arguments
        // Exit if the program arguments are worng
        if (argc != 3) {
            fprintf(stderr, "Error: Wrong program arguments\n");
            return 1;
        }

        // Load number of N-bites
        unsigned int nBites = atoi(argv[2]);
        int halfBites = nBites / 2;

        mpz_t p, q, n, phi, e, gcdRes, d;
    
        mpz_inits(p, q, n, phi, e, gcdRes, d, NULL);

        // Create file point to /dev/urandom
        // Used for getting random number generator seed
        FILE *fp = fopen("/dev/urandom", "r");

        // Init srand random generator
        srand(time(NULL));
        // Get initial seed value
        unsigned long int seed = abs(rand());
        
        // Generate random number generator seed
        for (int i = 0; i < 8; i++) {
            seed *= abs(fgetc(fp)) + seed;
        } 

        // Close file pointer (/dev/urandom)
        fclose(fp);

        // Create random number generator with seed from /dev/urandom
        gmp_randstate_t randommer;
        gmp_randinit_mt(randommer);
        gmp_randseed_ui(randommer, seed);

        // Generate both P and Q numbers
        // Calculate N with correct bite length
        while (mpz_sizeinbase(n, 2) != nBites) {
            getRandomPrimeBites(p, randommer, halfBites);
            getRandomPrimeBites(q, randommer, halfBites);
            mpz_mul(n, p, q);
        }
        
        // Calculate phi(n) (phi(n) = (p - 1) * (q - 1))
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);

        mpz_mul(phi, p, q);
        
        mpz_add_ui(p, p, 1);
        mpz_add_ui(q, q, 1);

        // Print out P, Q and N numbers
        gmp_printf("%#Zx %#Zx %#Zx ", p, q, n);

        // Calculate E - number, based on the following:
        // 1 < e < (phi(n)) && gcd(e, phi(n)) == 1
        while (mpz_cmp_ui(gcdRes, 1) != 0) {
            mpz_urandomm(e, randommer, phi);
            gcd(e, phi, gcdRes);
        }

        // Calculate Multiplicative inverse
        multiplicativeInverse(phi, e, d);
        
        // Print out both E and D numbers
        gmp_printf("%#Zx %#Zx\n", e, d);

        gmp_randclear(randommer);
        mpz_clears(p, q, n, phi, e, gcdRes, d, NULL);

    // Encrypt the message
    } else if (strcmp(prog_arg, "-e") == 0) {
        // Check number of the program arguments
        // Exit if the program arguments are worng
        if (argc != 5) {
            fprintf(stderr, "Error: Wrong program arguments\n");
            return 1;
        }

        mpz_t e, n, m, c;

        // Load keys from the program arguments
        mpz_init_set_str(e, argv[2], 0);
        mpz_init_set_str(n, argv[3], 0);
        mpz_init_set_str(m, argv[4], 0);
        mpz_init(c);

        // Encrypt the message
        encryptMessage(c, m, e, n);

        // Print ecnrypted message
        gmp_printf("%#Zx\n", c);

        mpz_clears(e, n, m, c, NULL);

    // Decrypt the message
    } else if (strcmp(prog_arg, "-d") == 0) {
        // Check number of the program arguments
        // Exit if the program arguments are worng
        if (argc != 5) {
            fprintf(stderr, "Error: Wrong program arguments\n");
            return 1;
        }

        mpz_t d, n, c, m;

        // Load keys from the program arguments
        mpz_init_set_str(d, argv[2], 0);
        mpz_init_set_str(n, argv[3], 0);
        mpz_init_set_str(c, argv[4], 0);
        mpz_init(m);

        // Decrypt the message
        decryptMessage(m, c, d, n);

        // Print decrypted message
        gmp_printf("%#Zx\n", m);

        mpz_clears(m, c, d, n, NULL);

    // Crack RSA keys by public modulus        
    } else if (strcmp(prog_arg, "-b") == 0) {
        // Check number of the program arguments
        // Exit if the program arguments are worng
        if (argc != 3) {
            fprintf(stderr, "Error: Wrong program arguments\n");
            return 1;
        }

        mpz_t n, p, q;
        mpz_init_set_str(n, argv[2], 0);
        mpz_inits(p, q, NULL);

        bool found = false;

        // Check, if the number N is divisible by any prime number up to 1 000 000
        for (unsigned long int i = 1; i < 1000000; i++) {
            if (mpz_divisible_ui_p(n, i) != 0) {
                mpz_set_ui(p, i);
                
                // Check, if the number that can divide the public modulus N
                // is a prime number
                if (isPrime(p) == true) {
                    // Check, if both dividend and devisor are prime numbers
                    mpz_divexact(q, n, p);
                    if (isPrime(q) == true) {
                        found = true;
                        break;
                    }
                }
            }
        }

        // If simple method did not work, use Fermat's factorization method
        if (found == false) {
            fermatsFactorization(n, p, q);
            
            // Check, if both dividend and devisor are prime numbers
            if (isPrime(p) == true && isPrime(q) == true) {
                found = true;
            }
        }

        // If we have found correct dividend and devisor, print one of them
        if (found == true) {
            gmp_printf("%#Zx\n", p);
        }

        mpz_clears(n, p, q, NULL);

    } else {
        // Uknown program argument
        fprintf(stderr, "Error: Unknown argument '%s'\n", prog_arg);
        return 1;
    }

    return 0;
}