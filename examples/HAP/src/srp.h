//WARNING: potential memory leak if functions are called out of order or repeated

/*
 * Secure Remote Password 6a implementation
 * Copyright (c) 2010 Tom Cocagne. All rights reserved.
 * https://github.com/cocagne/csrp
 *
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 Tom Cocagne
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

/* 
 * 
 * Purpose:       This is a direct implementation of the Secure Remote Password
 *                Protocol version 6a as described by 
 *                http://srp.stanford.edu/design.html
 * 
 * Author:        tom.cocagne@gmail.com (Tom Cocagne)
 * 
 * Dependencies:  OpenSSL (and Advapi32.lib on Windows)
 * 
 * Usage:         Refer to test_srp.c for a demonstration
 * 
 * Notes:
 *    This library allows multiple combinations of hashing algorithms and 
 *    prime number constants. For authentication to succeed, the hash and
 *    prime number constants must match between 
 *    srp_create_salted_verification_key(), srp_user_new(),
 *    and srp_verifier_new(). A recommended approach is to determine the
 *    desired level of security for an application and globally define the
 *    hash and prime number constants to the predetermined values.
 * 
 *    As one might suspect, more bits means more security. As one might also
 *    suspect, more bits also means more processing time. The test_srp.c 
 *    program can be easily modified to profile various combinations of 
 *    hash & prime number pairings.
 */

#ifndef SRP_H
#define SRP_H

#include <openssl/bn.h>
#include <openssl/sha.h>


typedef enum
{
    SRP_NG_3072,
    SRP_NG_CUSTOM
} SRP_NGType;

typedef enum 
{
    SRP_SHA1, 
    SRP_SHA224, 
    SRP_SHA256,
    SRP_SHA384, 
    SRP_SHA512
} SRP_HashAlgorithm;

typedef struct
{
	BIGNUM     * N;
	BIGNUM     * g;
} NGConstant;

class SRPVerifier
{
public:
	SRP_HashAlgorithm  hash_alg;
	NGConstant        *ng;

	const char          * username;
	BIGNUM              * v;
	BIGNUM              * b;
	BIGNUM              * s;
	BIGNUM              * B;		
	int                   authenticated;

	unsigned char M[SHA512_DIGEST_LENGTH];
	unsigned char H_AMK[SHA512_DIGEST_LENGTH];
	unsigned char session_key[SHA512_DIGEST_LENGTH];
	
	~SRPVerifier();
};


/* This library will automatically seed the OpenSSL random number generator
 * using cryptographically sound random data on Windows & Linux. If this is
 * undesirable behavior or the host OS does not provide a /dev/urandom file, 
 * this function may be called to seed the random number generator with 
 * alternate data.
 *
 * The random data should include at least as many bits of entropy as the
 * largest hash function used by the application. So, for example, if a
 * 512-bit hash function is used, the random data requies at least 512
 * bits of entropy.
 * 
 * Passing a null pointer to this function will cause this library to skip
 * seeding the random number generator. This is only legitimate if it is
 * absolutely known that the OpenSSL random number generator has already
 * been sufficiently seeded within the running application.
 * 
 * Notes: 
 *    * This function is optional on Windows & Linux and mandatory on all
 *      other platforms.
 */
void srp_random_seed( const unsigned char * random_data, int data_length );



/* Out: bytes_s, len_s
*
* The caller is responsible for freeing the memory allocated for bytes_s
*
*/

SRPVerifier * srp_create_salted_verifier( SRP_HashAlgorithm alg,
												 SRP_NGType ng_type, const char * username,
												 const unsigned char * password, int len_password,
												 const unsigned char ** bytes_s, int * len_s);

/* Out: bytes_B, len_B.
*
* On failure, bytes_B will be set to NULL and len_B will be set to 0
*/
void  srp_generate_public_key(SRPVerifier * ver, const unsigned char ** bytes_B, int * len_B);

void srp_compute_shared_secret(SRPVerifier * ver, const unsigned char * bytes_A, int len_A);

int                   srp_verifier_is_authenticated( SRPVerifier * ver );


const char *          srp_verifier_get_username( SRPVerifier * ver );

/* key_length may be null */
const unsigned char * srp_verifier_get_session_key( SRPVerifier * ver, int * key_length );


int                   srp_verifier_get_session_key_length( SRPVerifier * ver );


/* user_M must be exactly srp_verifier_get_session_key_length() bytes in size */
void                  srp_verifier_verify_session( SRPVerifier * ver,
                                                   const unsigned char * user_M, 
                                                   const unsigned char ** bytes_HAMK );

#endif /* Include Guard */
