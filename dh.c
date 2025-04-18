/* Diffie Hellman key exchange, and HKDF for key derivation. */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "dh.h"
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#include <libkern/OSByteOrder.h>

#include <assert.h>
#include "util.h"

mpz_t q; /* "small" prime; should be 256 bits or more */
mpz_t p; /* "large" prime; should be 2048 bits or more, with q|(p-1) */
mpz_t g; /* generator of the subgroup of order q */
/* length of q and p in bits and bytes (for convenience) */
size_t qBitlen;
size_t pBitlen;
size_t qLen; /* length of q in bytes */
size_t pLen; /* length of p in bytes */

/* NOTE: this constant is arbitrary and does not need to be secret. */
const char* hmacsalt = "z3Dow}^Z]8Uu5>pr#;{QUs!133";

int init(const char* fname)
{
	mpz_init(q);
	mpz_init(p);
	mpz_init(g);
	FILE* f = fopen(fname,"rb");
	if (!f) {
		fprintf(stderr, "Could not open file 'params'\n");
		return -1;
	}
	/* p is a 4096 bit prime, and g generates a subgroup of order q,
	 * which is a 512 bit prime. */
	int nvalues = gmp_fscanf(f,"q = %Zd\np = %Zd\ng = %Zd",q,p,g);
	fclose(f);
	if (nvalues != 3) {
		printf("couldn't parse parameter file\n");
		return -1;
	}

	/* now a sanity check on what we read: */
	if (!ISPRIME(q)) {
		printf("q not prime!\n");
		return -1;
	}
	if (!ISPRIME(p)) {
		printf("p not prime!\n");
		return -1;
	}
	/* now make sure that q divides the order of the multiplicative group: */
	/* temporaries to hold results */
	NEWZ(t);
	NEWZ(r);
	mpz_sub_ui(r,p,1); /* r = p-1 */
	if (!mpz_divisible_p(r,q)) {
		printf("q does not divide (p-1)!\n");
		return -1;
	}
	mpz_divexact(t,r,q); /* t = (p-1)/q */
	if (mpz_divisible_p(t,q)) {
		printf("q^2 divides (p-1)!\n");
		return -1;
	}
	/* make sure g is a generator (which almost surely will be the case) */
	mpz_powm(r,g,t,p); /* if r != 1, g is a generator since q is prime */
	if (mpz_cmp_ui(r,1) == 0) {
		printf("g does not generate subroup of order q!\n");
		return -1;
	}
	qBitlen = mpz_sizeinbase(q,2);
	pBitlen = mpz_sizeinbase(p,2);
	qLen = qBitlen / 8 + (qBitlen % 8 != 0);
	pLen = pBitlen / 8 + (pBitlen % 8 != 0);
	return 0;
}

int initFromScratch(size_t qbits, size_t pbits)
{
	/* select random prime q of the right number of bits, then multiply
	 * by a random even integer, add 1, check if that is prime.  If so,
	 * we've found q and p respectively. */
	/* lengths in BYTES: */
	qBitlen = qbits;
	pBitlen = pbits;
	qLen = qBitlen / 8 + (qBitlen % 8 != 0);
	pLen = pBitlen / 8 + (pBitlen % 8 != 0);
	size_t rLen = pLen - qLen;
	unsigned char* qCand = malloc(qLen);
	unsigned char* rCand = malloc(rLen);
	mpz_init(q);
	mpz_init(p);
	mpz_init(g);
	NEWZ(r); /* holds (p-1)/q */
	NEWZ(t); /* scratch space */
	FILE* f = fopen("/dev/urandom","rb");
	do {
		do {
			fread(qCand,1,qLen,f);
			BYTES2Z(q,qCand,qLen);
		} while (!ISPRIME(q));
		/* now try to get p */
		fread(rCand,1,rLen,f);
		rCand[0] &= 0xfe; /* set least significant bit to 0 (make r even) */
		BYTES2Z(r,rCand,rLen);
		mpz_mul(p,q,r);     /* p = q*r */
		mpz_add_ui(p,p,1);  /* p = p+1 */
		/* should make sure q^2 doesn't divide p-1.
		 * suffices to check if q|r */
		mpz_mod(t,r,q);     /* t = r%q */
		/* now check if t is 0: */
		if (mpz_cmp_ui(t,0) == 0) continue; /* really unlucky! */
	} while (!ISPRIME(p));
	gmp_printf("q = %Zd\np = %Zd\n",q,p);
	/* now find a generator of the subgroup of order q.
	 * Turns out just about anything to the r power will work: */
	size_t tLen = qLen; /* qLen somewhat arbitrary. */
	unsigned char* tCand = malloc(tLen);
	do {
		fread(tCand,1,tLen,f);
		BYTES2Z(t,tCand,tLen);
		if (mpz_cmp_ui(t,0) == 0) continue; /* really unlucky! */
		mpz_powm(g,t,r,p); /* efficiently do g = t**r % p */
	} while (mpz_cmp_ui(g,1) == 0); /* since q prime, any such g /= 1
									   will actually be a generator of
									   the subgroup. */
	fclose(f);
	gmp_printf("g = %Zd\n",g);
	return 0;
}

/* choose random exponent sk and compute g^(sk) mod p.
 * NOTE: init or initFromScratch must have been called first. */
int dhGen(mpz_t sk, mpz_t pk)
{
	FILE* f = fopen("/dev/urandom","rb");
	if (!f) {
		fprintf(stderr, "Failed to open /dev/urandom\n");
		return -1;
	}
	size_t buflen = qLen + 32; /* read extra to get closer to uniform distribution */
	unsigned char* buf = malloc(buflen);
	fread(buf,1,buflen,f);
	fclose(f);
	NEWZ(a);
	BYTES2Z(a,buf,buflen);
	mpz_mod(sk,a,q);
	mpz_powm(pk,g,sk,p);
	return 0;
}

int dhGenk(dhKey* k)
{
	assert(k);
	initKey(k);
	return dhGen(k->SK,k->PK);
}

/* see "Cryptographic Extraction and Key Derivation: The HKDF Scheme"
 * by H. Krawczyk, 2010 for details on the key derivation used here. */
int dhFinal(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char* keybuf, size_t buflen)
{
	NEWZ(x);
	mpz_powm(x,pk_yours,sk_mine,p);
	/* now apply key derivation to get the desired number of bytes: */
	unsigned char* SK = malloc(pLen);
	memset(SK,0,pLen);
	size_t nWritten; /* saves number of bytes written by Z2BYTES */
	Z2BYTES(SK,&nWritten,x);
	const size_t maclen = 64; /* output len of sha512 */
	unsigned char PRK[maclen];
	memset(PRK,0,maclen);
	HMAC(EVP_sha512(),hmacsalt,strlen(hmacsalt),SK,nWritten,PRK,0);
	/* Henceforth, use PRK as the HMAC key.  The initial chunk of derived key
	 * is computed as HMAC_{PRK}(CTX || 0), where CTX = pk_A || pk_B, where
	 * (pk_A,pk_B) is {pk_mine,pk_yours}, sorted ascending.
	 * To generate further chunks K(i+1), proceed as follows:
	 * K(i+1) = HMAC_{PRK}(K(i) || CTX || i). */
	/* For convenience (?) we'll use a buffer named CTX that will contain
	 * the previous key as well as the index i:
	 *         +------------------------+
	 *  CTX == | K(i) | PK_A | PK_B | i |
	 *         +------------------------+
	 * */
	const size_t ctxlen = maclen + 2*pLen + 8;
	/* NOTE: the extra 8 bytes are to concatenate the key chunk index */
	unsigned char* CTX = malloc(ctxlen);
	uint64_t index = 0;       /* key index */
	uint64_t indexBE = index; /* key index, but always big endian */
	memset(CTX,0,ctxlen);
	if (mpz_cmp(pk_mine,pk_yours) < 0) {
		Z2BYTES(CTX+maclen,NULL,pk_mine);
		Z2BYTES(CTX+maclen+pLen,NULL,pk_yours);
	} else {
		Z2BYTES(CTX+maclen,NULL,pk_yours);
		Z2BYTES(CTX+maclen+pLen,NULL,pk_mine);
	}
	memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE));
	unsigned char K[maclen];
	memset(K,0,maclen);
	/* compute initial key chunk: */
	HMAC(EVP_sha512(),PRK,maclen,CTX,ctxlen,K,0);
	/* and write to the output key buffer: */
	size_t copylen = (buflen < maclen)?buflen:maclen;
	memcpy(keybuf,K,copylen);
	size_t bytesLeft = buflen - copylen;
	while (bytesLeft) {
		/* compute next chunk and copy */
		index++;
		indexBE = OSSwapHostToBigInt64(index);
		memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE));
		memcpy(CTX,K,maclen);
		HMAC(EVP_sha512(),PRK,maclen,CTX,ctxlen,K,0);
		copylen = (bytesLeft < maclen)?bytesLeft:maclen;
		/* move to next chunk of key buffer */
		keybuf += maclen;
		memcpy(keybuf,K,copylen);
		bytesLeft -= copylen;
	}
	/* erase sensitive data: */
	memset(CTX,0,ctxlen);
	memset(K,0,maclen);
	memset(SK,0,pLen);
	memset(PRK,0,maclen);
	return 0;
}

int dh3Final(mpz_t a, mpz_t A, mpz_t x, mpz_t X, mpz_t B, mpz_t Y,
		unsigned char* keybuf, size_t buflen)
{
	/* the 3 DH values will be stored in
	 * AY == Y^a
	 * XY == Y^x
	 * XB == B^x
	 * NOTE: so that both parties derive the same key, we'll swap(AY,XB)
	 * if necessary, based on whether or not A < B. */
	NEWZ(AY);
	mpz_powm(AY,Y,a,p);
	NEWZ(XY);
	mpz_powm(XY,Y,x,p);
	NEWZ(XB);
	mpz_powm(XB,B,x,p);
	if (mpz_cmp(A,B) > 0) {
		mpz_swap(AY,XB);
	}
	/* now apply key derivation to get the desired number of bytes: */
	size_t kmlen = 3*pLen; /* length of raw key material (AY || XY || XB) */
	unsigned char* KM = malloc(kmlen);
	memset(KM,0,kmlen);
	/* NOTE: we discard number of bytes actually written by Z2BYTES and always
	 * use kmlen, so it is important that we 0 the buffer first. */
	Z2BYTES(KM,NULL,AY);
	Z2BYTES(KM+pLen,NULL,XY);
	Z2BYTES(KM+2*pLen,NULL,XB);
	const size_t maclen = 64; /* output len of sha512 */
	unsigned char PRK[maclen];
	memset(PRK,0,maclen);
	HMAC(EVP_sha512(),hmacsalt,strlen(hmacsalt),KM,kmlen,PRK,0);
	/* Henceforth, use PRK as the HMAC key.  The initial chunk of derived key
	 * is computed as HMAC_{PRK}(CTX || 0), where CTX = X || Y, the concatenation
	 * of the ephemeral public keys, sorted ascending.
	 * To generate further chunks K(i+1), proceed as follows:
	 * K(i+1) = HMAC_{PRK}(K(i) || CTX || i). */
	/* For convenience (?) we'll use a buffer named CTX that will contain
	 * the previous key as well as the index i:
	 *         +------------------+
	 *  CTX == | K(i) | X | Y | i |
	 *         +------------------+
	 * */
	const size_t ctxlen = maclen + 2*pLen + 8;
	/* NOTE: the extra 8 bytes are to concatenate the key chunk index */
	unsigned char* CTX = malloc(ctxlen);
	uint64_t index = 0;       /* key index */
	uint64_t indexBE = index; /* key index, but always big endian */
	memset(CTX,0,ctxlen);
	/* NOTE: shouldn't swap X,Y since mpz_t params are effectively by-reference */
	if (mpz_cmp(X,Y) < 0) {
		Z2BYTES(CTX+maclen,NULL,X);
		Z2BYTES(CTX+maclen+pLen,NULL,Y);
	} else {
		Z2BYTES(CTX+maclen,NULL,Y);
		Z2BYTES(CTX+maclen+pLen,NULL,X);
	}
	memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE));
	unsigned char K[maclen];
	memset(K,0,maclen);
	/* compute initial key chunk: */
	HMAC(EVP_sha512(),PRK,maclen,CTX,ctxlen,K,0);
	/* and write to the output key buffer: */
	size_t copylen = (buflen < maclen)?buflen:maclen;
	memcpy(keybuf,K,copylen);
	size_t bytesLeft = buflen - copylen;
	while (bytesLeft) {
		/* compute next chunk and copy */
		index++;
		indexBE = OSSwapHostToBigInt64(index);
		memcpy(CTX+maclen+2*pLen,&indexBE,sizeof(indexBE));
		memcpy(CTX,K,maclen);
		HMAC(EVP_sha512(),PRK,maclen,CTX,ctxlen,K,0);
		copylen = (bytesLeft < maclen)?bytesLeft:maclen;
		/* move to next chunk of key buffer */
		keybuf += maclen;
		memcpy(keybuf,K,copylen);
		bytesLeft -= copylen;
	}
	/* erase sensitive data: */
	memset(CTX,0,ctxlen);
	memset(K,0,maclen);
	memset(KM,0,pLen);
	memset(PRK,0,maclen);
	return 0;
}

int dh3Finalk(dhKey* skA, dhKey* skX, dhKey* pkB, dhKey* pkY,
		unsigned char* keybuf, size_t buflen)
{
	assert(skA && skX && pkB && pkY);
	/* make sure secret key pieces are present: */
	assert(mpz_cmp_ui(skA->SK,0) > 0 && mpz_cmp_ui(skX->SK,0) > 0);
	return dh3Final(skA->SK,skA->PK,skX->SK,skX->PK,pkB->PK,pkY->PK,keybuf,buflen);
}


// NEW FUNCTIONS 

// CREATING A SIGNATURE
int sign_dh_pubkey(mpz_t pubkey, unsigned char* sig, size_t* siglen, const char* privkey_path) {
    // convert mpz_t to byte array
    unsigned char buf[512];  // size being used
    size_t n;

    Z2BYTES(buf, &n, pubkey);
    if (n > sizeof(buf)) {
        fprintf(stderr, "Public key too large to sign\n");
        return -1;
    }

    // open private key file
    FILE* f = fopen(privkey_path, "r");
    if (!f) {
        perror("Failed to open private key file");
        return -1;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "Failed to read private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

	// initialize signing context
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create digest context\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
		fprintf(stderr, "EVP_DigestSignInit failed\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return -1;
	}

	// determine signature length
	if (EVP_DigestSign(ctx, NULL, siglen, buf, n) <= 0) {
		fprintf(stderr, "Failed to get signature length\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return -1;
	}

	// sign the data
	if (EVP_DigestSign(ctx, sig, siglen, buf, n) <= 0) {
		fprintf(stderr, "Failed to generate signature\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		return -1;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return 0;
}

// SENDING SIGNATURE AND PUBLIC KEY
int send_dh_pubkey_with_sig(int sockfd, mpz_t pubkey, const char* privkey_path) {
    unsigned char pubkey_bytes[512];     
    size_t pubkey_len;
    Z2BYTES(pubkey_bytes, &pubkey_len, pubkey);  // Convert mpz_t to bytes

    unsigned char sig[512];  // should match RSA key size 
    size_t sig_len;

    if (sign_dh_pubkey(pubkey, sig, &sig_len, privkey_path) != 0) {
        fprintf(stderr, "Failed to sign DH public key\n");
        return -1;
    }

    // Build message buffer
    uint16_t net_pubkey_len = htons((uint16_t)pubkey_len);
    uint16_t net_sig_len    = htons((uint16_t)sig_len);

    size_t total_len = 2 + pubkey_len + 2 + sig_len;
    unsigned char* buffer = malloc(total_len);
    if (!buffer) {
        perror("malloc");
        return -1;
    }

    // Construct message layout
    size_t offset = 0;
    memcpy(buffer + offset, &net_pubkey_len, 2); offset += 2;
    memcpy(buffer + offset, pubkey_bytes, pubkey_len); offset += pubkey_len;
    memcpy(buffer + offset, &net_sig_len, 2); offset += 2;
    memcpy(buffer + offset, sig, sig_len);

	// TESTING 
	/* printf("Sending DH pubkey (%zu bytes)\n", pubkey_len);
	printf("Sending signature (%zu bytes)\n", sig_len);

	printf("DH pubkey (hex): ");
	for (size_t i = 0; i < pubkey_len; i++) printf("%02x", pubkey_bytes[i]);
	printf("\n");

	printf("Signature (hex): ");
	for (size_t i = 0; i < sig_len; i++) printf("%02x", sig[i]);
	printf("\n");

	printf("Total bytes to send: %zu\n", total_len); */

    // Send message
    ssize_t sent = send(sockfd, buffer, total_len, 0);
    if (sent != total_len) {
        fprintf(stderr, "Failed to send full DH pubkey+sig (sent %zd / %zu)\n", sent, total_len);
        free(buffer);
        return -1;
    }

    free(buffer);		// memory handling
    return 0;
}

// RECIEVING SIGNATURE AND PUBLIC KEY
int recv_dh_pubkey_with_sig(int sockfd, mpz_t* pubkey_out, unsigned char* sig_out, size_t* siglen_out) {
    uint16_t net_pubkey_len, net_sig_len;
    ssize_t r;

    // read pubkey length
    r = recv(sockfd, &net_pubkey_len, 2, MSG_WAITALL);
    if (r != 2) {
        perror("Failed to read pubkey length");
        return -1;
    }
    size_t pubkey_len = ntohs(net_pubkey_len);

    // read pubkey bytes
    unsigned char* pubkey_buf = malloc(pubkey_len);
    if (!pubkey_buf) return -1;

    r = recv(sockfd, pubkey_buf, pubkey_len, MSG_WAITALL);
    if (r != (ssize_t)pubkey_len) {
        perror("Failed to read pubkey");
        free(pubkey_buf);
        return -1;
    }

    // convert to mpz_t
    mpz_init(*pubkey_out);
    BYTES2Z(*pubkey_out, pubkey_buf, pubkey_len);
    free(pubkey_buf);

    // read signature length
    r = recv(sockfd, &net_sig_len, 2, MSG_WAITALL);
    if (r != 2) {
        perror("Failed to read sig length");
        return -1;
    }
    *siglen_out = ntohs(net_sig_len);

    // read signature bytes
    r = recv(sockfd, sig_out, *siglen_out, MSG_WAITALL);
    if (r != (ssize_t)*siglen_out) {
        perror("Failed to read signature");
        return -1;
    }

	// TESTING
	/* printf("Received pubkey len: %zu\n", pubkey_len);
	printf("Received sig len: %zu\n", *siglen_out); */

    // Done
    return 0;
}

int verify_dh_pubkey(mpz_t pubkey, unsigned char* sig, size_t siglen, const char* pubkey_path) {
    unsigned char buf[512];  // match your max DH size
    size_t buflen;

    // Convert pubkey to bytes
    Z2BYTES(buf, &buflen, pubkey);

	// TESTING
	/* printf("📥 Verifying pubkey bytes (%zu):\n", buflen);
	for (size_t i = 0; i < buflen; i++) printf("%02x", buf[i]);
	printf("\n"); */


    // load public key
    FILE* f = fopen(pubkey_path, "r");
    if (!f) {
        perror("Could not open public key file");
        return -1;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        fprintf(stderr, "Failed to read public key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // setup verification context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }


    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0 ||
        EVP_DigestVerify(ctx, sig, siglen, buf, buflen) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;  // Signature did not verify
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;  // Signature verified
}