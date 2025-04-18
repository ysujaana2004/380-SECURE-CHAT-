#include <stdio.h>
#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "dh.h"  // contains the declaration for sign_dh_pubkey

int main() {
    // Initialize a sample DH public key (replace with actual one in real use)
    mpz_t pubkey;
    mpz_init_set_str(pubkey, "123456789012345678901234567890", 10);

    unsigned char sig[256];  // Make sure this is big enough for your RSA key size
    size_t siglen;

    const char* privkey_path = "alice_priv.pem";  // Make sure this file exists

    if (sign_dh_pubkey(pubkey, sig, &siglen, privkey_path) == 0) {
        printf("Signature (%zu bytes):\n", siglen);
        for (size_t i = 0; i < siglen; i++)
            printf("%02x", sig[i]);
        printf("\n");
    } else {
        printf("Signing failed.\n");
    }

    mpz_clear(pubkey);
    return 0;
}
