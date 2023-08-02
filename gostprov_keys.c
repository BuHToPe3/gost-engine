// Code inspired by OpenSSL common provider and OQS provider code

#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string.h>
#include <assert.h>
#include "gost_prov.h" 

typedef enum {
    KEY_OP_PUBLIC,
    KEY_OP_PRIVATE,
    KEY_OP_KEYGEN
} gostprov_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char* tlsname;
    char* gostname;
    int keytype;
    int secbits;
} gostprov_nid_name_t;

static int gostprov_key_recreate_classickey(GOSTPROV_KEY *key, gostprov_key_op_t op);

#define NID_TABLE_LEN 1

static gostprov_nid_name_t nid_names[NID_TABLE_LEN] = {
       { 0, "gost2012_256", "GOST2012_256", KEY_TYPE_SIG, 256 },
};

int gostprov_set_nid(char* tlsname, int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (!strcmp(nid_names[i].tlsname, tlsname)) {
          nid_names[i].nid = nid;
          return 1;
      }
   }
   return 0;
}

static int get_secbits(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].secbits;
   }
   return 0; 
}

static int get_keytype(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].keytype;
   }
   return 0; 
}

static char* get_gostname(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return nid_names[i].gostname;
   }
   return 0; 
}

static int get_gostalg_idx(int nid) {
   int i;
   for(i=0;i<NID_TABLE_LEN;i++) {
      if (nid_names[i].nid == nid)
          return i;
   }
   return -1; 
}

/* Prepare composite data structures. RetVal 0 is error. */
static int gostprov_key_set_composites(GOSTPROV_KEY *key) {
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

PROV_CTX *gostprov_newprovctx(OSSL_LIB_CTX *libctx, const OSSL_CORE_HANDLE *handle) {
    PROV_CTX * ret = OPENSSL_zalloc(sizeof(PROV_CTX));
    if (ret) {
       ret->libctx = libctx;
       ret->core_handle = handle;
       //ret->corebiometh = bm;
    }
    return ret;
}

void gostprov_freeprovctx(PROV_CTX *ctx) {
    OSSL_LIB_CTX_free(ctx->libctx);
    //BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}


void gostprov_key_set0_libctx(GOSTPROV_KEY *key, OSSL_LIB_CTX *libctx)
{
    key->libctx = libctx;
}

static GOSTPROV_KEY *gostprov_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq, int nid) {
	GOSTPROV_PRINTF2("Generating GOSTPROV key for nid %d\n", nid);

	char* tls_algname = (char *)OBJ_nid2sn(nid);
	GOSTPROV_PRINTF2("                    for tls_name %s\n", tls_algname);

	if (!tls_algname) {
		ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
		return NULL;
	}

	return gostprov_key_new(libctx, get_gostname(nid), tls_algname, get_keytype(nid), propq, get_secbits(nid), get_gostalg_idx(nid));
}

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY* setECParams(EVP_PKEY *eck, int nid) {
    const unsigned char p256params[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const unsigned char p384params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    const unsigned char p521params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

    const unsigned char* params;
    switch(nid) {
        case NID_X9_62_prime256v1:
            params = p256params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
        case NID_secp384r1:
            params = p384params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
        case NID_secp521r1:
            params = p521params;
            return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
        default:
            return NULL;
    }
}

static GOSTPROV_KEY *gostprov_key_op(const X509_ALGOR *palg,
                      const unsigned char *p, int plen,
                      gostprov_key_op_t op,
                      OSSL_LIB_CTX *libctx, const char *propq)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return NULL;
}

/* Recreate EVP data structure after import. RetVal 0 is error. */
static int gostprov_key_recreate_classickey(GOSTPROV_KEY *key, gostprov_key_op_t op) 
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

GOSTPROV_KEY *gostprov_key_from_x509pubkey(const X509_PUBKEY *xpk,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return NULL;
}

GOSTPROV_KEY *gostprov_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return NULL;
}

static int gostprov_hybsig_init(int bit_security, GOSTPROV_EVP_CTX *evp_ctx, char* algname)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

static const int gostprov_hybkem_init_ecp(char* tls_name, GOSTPROV_EVP_CTX *evp_ctx)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

static const int gostprov_hybkem_init_ecx(char* tls_name, GOSTPROV_EVP_CTX *evp_ctx)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

//static const int (*init_kex_fun[])(char *, GOSTPROV_EVP_CTX *) = {
//        gostprov_hybkem_init_ecp,
//        gostprov_hybkem_init_ecx
//};
#ifdef USE_ENCODING_LIB
extern const char* gostprov_alg_encoding_list[];
#endif
extern const char* gostprov_oid_alg_list[];

GOSTPROV_KEY *gostprov_key_new(OSSL_LIB_CTX *libctx, char* gost_name, char* tls_name, int primitive, const char *propq, int bit_security, int alg_idx)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return NULL;
}

void gostprov_key_free(GOSTPROV_KEY *key)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return;
}

int gostprov_key_up_ref(GOSTPROV_KEY *key)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

int gostprov_key_fromdata(GOSTPROV_KEY *key, const OSSL_PARAM params[], int include_private)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_key_gen_oqs(GOSTPROV_KEY *key, int gen_kem) {
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of pubkey/privkey buffers;
 * returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY* gostprov_key_gen_evp_key(GOSTPROV_EVP_CTX *ctx, unsigned char *pubkey, unsigned char *privkey)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return NULL;
}

int gostprov_key_gen(GOSTPROV_KEY *key)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

int gostprov_key_secbits(GOSTPROV_KEY *key) {
    return key->bit_security;
}

int gostprov_key_maxsize(GOSTPROV_KEY *key) {
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

int gostprov_key_get_gost_public_key_len(GOSTPROV_KEY *k) {
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}
