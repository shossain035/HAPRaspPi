#ifndef _Included_Curve25519Donna
#define _Included_Curve25519Donna
#ifdef __cplusplus
extern "C" {
#endif

void curve25519_donna(unsigned char *output, const unsigned char *a, const unsigned char *b);

#ifdef __cplusplus
}
#endif
#endif
