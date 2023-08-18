/**********************************************************************
 *                 gost_prov.h - The provider itself                  *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/engine.h>

#define GOSTPROV_PRINTF(a) printf(a)
#define GOSTPROV_PRINTF2(a, b) printf(a, b)
#define GOSTPROV_PRINTF3(a, b, c) printf(a, b, c)

// internal, but useful OSSL define:
#ifndef OSSL_NELEM
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#endif
/* gostprov error codes */
#define GOSTPROV_R_NOT_IMPLEMENTED                            255

/* helper structure for classic key components in hybrid keys.
 * Actual tables in oqsprov_keys.c
 */
 
struct gostprov_evp_info_st {
    int keytype;
    int nid;
    int raw_key_support;
    size_t length_public_key;
    size_t length_private_key;
    size_t kex_length_secret;
    size_t length_signature;
};

typedef struct gostprov_evp_info_st GOSTPROV_EVP_INFO;

struct gostprov_evp_ctx_st {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *keyParam;
    const GOSTPROV_EVP_INFO *evp_info;
};

typedef struct gostprov_evp_ctx_st GOSTPROV_EVP_CTX;

typedef union {//TODO
    //GOSTPROV_SIG *sig; 
    //GOSTPROV_KEM *kem;
} GOSTPROV_QS_CTX;

struct gostprov_provider_ctx_st {
    GOSTPROV_QS_CTX gostprov_qs_ctx;
    GOSTPROV_EVP_CTX *gostprov_evp_ctx;
};

typedef struct gostprov_provider_ctx_st GOSTPROV_PROVIDER_CTX;

#ifdef USE_ENCODING_LIB
struct oqsx_provider_encoding_ctx_st {
    const qsc_encoding_t* encoding_ctx;
    const qsc_encoding_impl_t* encoding_impl;
};

typedef struct oqsx_provider_encoding_ctx_st OQSX_ENCODING_CTX;
#endif

enum gostprov_key_type_en { //TODO Are we need this?
    KEY_TYPE_SIG, KEY_TYPE_KEM, KEY_TYPE_ECP_HYB_KEM, KEY_TYPE_ECX_HYB_KEM, KEY_TYPE_HYB_SIG
};

typedef enum gostprov_key_type_en GOSTPROV_KEY_TYPE;

struct gostprov_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    GOSTPROV_KEY_TYPE keytype;
    GOSTPROV_PROVIDER_CTX gostprov_provider_ctx;
#ifdef USE_ENCODING_LIB
    OQSX_ENCODING_CTX oqsx_encoding_ctx;
#endif
    EVP_PKEY *classical_pkey; // for hybrid sigs
    const GOSTPROV_EVP_INFO *evp_info;
    size_t numkeys;

    /* key lengths including size fields for classic key length information: (numkeys-1)*SIZE_OF_UINT32
     */
    size_t privkeylen;
    size_t pubkeylen;
    size_t bit_security;
    char *tls_name;
    _Atomic int references;

    /* point to actual priv key material -- classic key, if present, first
     * i.e., OQS key always at comp_*key[numkeys-1]
     */
    void **comp_privkey;
    void **comp_pubkey;

    /* contain key material: First SIZE_OF_UINT32 bytes indicating actual classic 
     * key length in case of hybrid keys (if numkeys>1)
     */
    void *privkey;
    void *pubkey;
};

typedef struct gostprov_key_st GOSTPROV_KEY;

struct provider_ctx_st {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;

    /*
     * "internal" GOST engine, which is the implementation that all the
     * provider functions will use to access the crypto functionality.
     * This is pure hackery, but allows us to quickly wrap all the ENGINE
     * function with provider wrappers.  There is no other supported way
     * to do this.
     */
    ENGINE *e;
	BIO_METHOD *corebiometh;
};
typedef struct provider_ctx_st PROV_CTX;

# define GOSTPROV_LIBCTX_OF(provctx) (((PROV_CTX *)provctx)->libctx)



/* Register given NID with tlsname in OSSL3 registry */
int gostprov_set_nid(char* tlsname, int nid);

/* Create OQSX_KEY data structure based on parameters; key material allocated separately */ 
GOSTPROV_KEY *gostprov_key_new(OSSL_LIB_CTX *libctx, char* gost_name, char* tls_name, int is_kem, const char *propq, int bit_security, int alg_idx);

/* allocate key material; component pointers need to be set separately */
int gostprov_key_allocate_keymaterial(GOSTPROV_KEY *key, int include_private);

/* free all data structures, incl. key material */
void gostprov_key_free(GOSTPROV_KEY *key);

/* increase reference count of given key */
int gostprov_key_up_ref(GOSTPROV_KEY *key);

/* do (composite) key generation */
int gostprov_key_gen(GOSTPROV_KEY *key);

/* create OQSX_KEY from pkcs8 data structure */
GOSTPROV_KEY *gostprov_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const char *propq);

/* create OQSX_KEY (public key material only) from X509 data structure */
GOSTPROV_KEY *gostprov_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx, const char *propq);

/* Backend support */
/* populate key material from parameters */
int gostprov_key_fromdata(GOSTPROV_KEY *gostxk, const OSSL_PARAM params[],
                     int include_private);
/* retrieve security bit count for key */
int gostprov_key_secbits(GOSTPROV_KEY *k);
/* retrieve pure OQS key len */
int gostprov_key_get_oqs_public_key_len(GOSTPROV_KEY *k);
/* retrieve maximum size of generated artifact (shared secret or signature, respectively) */
int gostprov_key_maxsize(GOSTPROV_KEY *k);
void gostprov_key_set0_libctx(GOSTPROV_KEY *key, OSSL_LIB_CTX *libctx);
int gostprov_patch_codepoints(void);

/* Function prototypes */

extern const OSSL_DISPATCH gostprov_generic_kem_functions[];
extern const OSSL_DISPATCH gostprov_hybrid_kem_functions[];
extern const OSSL_DISPATCH gostprov_signature_functions[];

///// ENDECODER_FUNCTIONS_START
extern const OSSL_DISPATCH gostprov_gost2012_256_to_PrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_EncryptedPrivateKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_EncryptedPrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH gostprov_gost2012_256_to_text_encoder_functions[];

extern const OSSL_DISPATCH gostprov_PrivateKeyInfo_der_to_gost2012_256_decoder_functions[];
extern const OSSL_DISPATCH gostprov_SubjectPublicKeyInfo_der_to_gost2012_256_decoder_functions[];
extern const OSSL_DISPATCH gostprov_PrivateKeyInfo_der_to_hash_with_sign12_256_decoder_functions[];
extern const OSSL_DISPATCH gostprov_SubjectPublicKeyInfo_der_to_hash_with_sign12_256_decoder_functions[];
///// ENDECODER_FUNCTIONS_END

extern const OSSL_DISPATCH gostprov_gost2012_256_keymgmt_functions[];
extern const OSSL_DISPATCH gostprov_hash_with_sign12_256_keymgmt_functions[];

/* BIO function declarations */
int gostprov_bio_from_dispatch(const OSSL_DISPATCH *fns);

OSSL_CORE_BIO *gostprov_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *gostprov_bio_new_membuf(const char *filename, int len);
int gostprov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read);
int gostprov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written);
int gostprov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size);
int gostprov_bio_puts(OSSL_CORE_BIO *bio, const char *str);
int gostprov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr);
int gostprov_bio_up_ref(OSSL_CORE_BIO *bio);
int gostprov_bio_free(OSSL_CORE_BIO *bio);
int gostprov_bio_vprintf(OSSL_CORE_BIO *bio, const char *format, va_list ap);
int gostprov_bio_printf(OSSL_CORE_BIO *bio, const char *format, ...);

BIO_METHOD *gostprov_bio_prov_init_bio_method(void);
BIO *gostprov_bio_new_from_core_bio(PROV_CTX *provctx, OSSL_CORE_BIO *corebio);

