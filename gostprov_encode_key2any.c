// Code inspired by OpenSSL common provider and OQS provider code

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>      /* PKCS8_encrypt() */
#include <openssl/proverr.h>
#include <string.h>
#include "gostprov_endecoder_local.h"

struct key2any_ctx_st {
    PROV_CTX *provctx;

    /* Set to 0 if parameters should not be saved (dsa only) */
    int save_parameters;

    /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
    int cipher_intent;

    EVP_CIPHER *cipher;

    OSSL_PASSPHRASE_CALLBACK *pwcb;
    void *pwcbarg;
};

typedef int check_key_type_fn(const void *key, int nid);
typedef int key_to_paramstring_fn(const void *key, int nid, int save,
                                  void **str, int *strtype);
typedef int key_to_der_fn(BIO *out, const void *key,
                          int key_nid, const char *pemname,
                          key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                          struct key2any_ctx_st *ctx);
typedef int write_bio_of_void_fn(BIO *bp, const void *x);


/* Free the blob allocated during key_to_paramstring_fn */
static void free_asn1_data(int type, void *data)
{
    switch(type) {
    case V_ASN1_OBJECT:
        ASN1_OBJECT_free(data);
        break;
    case V_ASN1_SEQUENCE:
        ASN1_STRING_free(data);
        break;
    }
}

static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,
                                          void *params, int params_type,
                                          i2d_of_void *k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final PKCS#8 info */
    PKCS8_PRIV_KEY_INFO *p8info = NULL;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_p8info called\n");

    if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
			    V_ASN1_UNDEF, NULL, 
			    der, derlen)) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        p8info = NULL;
    }

    return p8info;
}

static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info,
                                 struct key2any_ctx_st *ctx)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return NULL;
}

static X509_SIG *key_to_encp8(const void *key, int key_nid,
                              void *params, int params_type,
                              i2d_of_void *k2d, struct key2any_ctx_st *ctx)
{
    PKCS8_PRIV_KEY_INFO *p8info =
        key_to_p8info(key, key_nid, params, params_type, k2d);
    X509_SIG *p8 = NULL;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_encp8 called\n");

    if (p8info == NULL) {
        free_asn1_data(params_type, params);
    } else {
        p8 = p8info_to_encp8(p8info, ctx);
        PKCS8_PRIV_KEY_INFO_free(p8info);
    }
    return p8;
}

static X509_PUBKEY *gostprov_key_to_pubkey(const void *key, int key_nid,
                                  void *params, int params_type,
                                  i2d_of_void k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final X509_PUBKEY */
    X509_PUBKEY *xpk = NULL;

    GOSTPROV_PRINTF2("GOSTPROV provider: gostprov_key_to_pubkey called for NID %d\n", key_nid);

    if ((xpk = X509_PUBKEY_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid),
                        V_ASN1_UNDEF, NULL,
			der, derlen)) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        xpk = NULL;
    }

    return xpk;
}

/*
 * key_to_epki_* produce encoded output with the private key data in a
 * EncryptedPrivateKeyInfo structure (defined by PKCS#8).  They require
 * that there's an intent to encrypt, anything else is an error.
 *
 * key_to_pki_* primarly produce encoded output with the private key data
 * in a PrivateKeyInfo structure (also defined by PKCS#8).  However, if
 * there is an intent to encrypt the data, the corresponding key_to_epki_*
 * function is used instead.
 *
 * key_to_spki_* produce encoded output with the public key data in an
 * X.509 SubjectPublicKeyInfo.
 *
 * Key parameters don't have any defined envelopment of this kind, but are
 * included in some manner in the output from the functions described above,
 * either in the AlgorithmIdentifier's parameter field, or as part of the
 * key data itself.
 */

static int key_to_epki_der_priv_bio(BIO *out, const void *key,
                                    int key_nid,
                                    ossl_unused const char *pemname,
                                    key_to_paramstring_fn *p2s,
                                    i2d_of_void *k2d,
                                    struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_SIG *p8;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_epki_der_priv_bio called\n");

    if (!ctx->cipher_intent)
        return 0;

    if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters,
                            &str, &strtype))
        return 0;

    p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if (p8 != NULL)
        ret = i2d_PKCS8_bio(out, p8);

    X509_SIG_free(p8);

    return ret;
}

static int key_to_epki_pem_priv_bio(BIO *out, const void *key,
                                    int key_nid,
                                    ossl_unused const char *pemname,
                                    key_to_paramstring_fn *p2s,
                                    i2d_of_void *k2d,
                                    struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_SIG *p8;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_epki_pem_priv_bio called\n");

    if (!ctx->cipher_intent)
        return 0;

    if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters,
                            &str, &strtype))
        return 0;

    p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);
    if (p8 != NULL)
        ret = PEM_write_bio_PKCS8(out, p8);

    X509_SIG_free(p8);

    return ret;
}

static int key_to_pki_der_priv_bio(BIO *out, const void *key,
                                   int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s,
                                   i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    PKCS8_PRIV_KEY_INFO *p8info;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_pki_der_priv_bio called\n");

    if (ctx->cipher_intent)
        return key_to_epki_der_priv_bio(out, key, key_nid, pemname,
                                        p2s, k2d, ctx);

    if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters,
                            &str, &strtype))
        return 0;

    p8info = key_to_p8info(key, key_nid, str, strtype, k2d);

    if (p8info != NULL)
        ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);
    else
        free_asn1_data(strtype, str);

    PKCS8_PRIV_KEY_INFO_free(p8info);

    return ret;
}

static int key_to_pki_pem_priv_bio(BIO *out, const void *key,
                                   int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s,
                                   i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    PKCS8_PRIV_KEY_INFO *p8info;

    GOSTPROV_PRINTF("GOSTPROV provider: key_to_pki_pem_priv_bio called\n");

    if (ctx->cipher_intent)
        return key_to_epki_pem_priv_bio(out, key, key_nid, pemname,
                                        p2s, k2d, ctx);

    if (p2s != NULL && !p2s(key, key_nid, ctx->save_parameters,
                            &str, &strtype))
        return 0;

    p8info = key_to_p8info(key, key_nid, str, strtype, k2d);

    if (p8info != NULL)
        ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);
    else
        free_asn1_data(strtype, str);

    PKCS8_PRIV_KEY_INFO_free(p8info);

    return ret;
}

static int key_to_spki_der_pub_bio(BIO *out, const void *key,
                                   int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s,
                                   i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx)
{
	GOSTPROV_PRINTF("GOSTPROV provider: key_to_spki_der_pub_bio\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int key_to_spki_pem_pub_bio(BIO *out, const void *key,
                                   int key_nid,
                                   ossl_unused const char *pemname,
                                   key_to_paramstring_fn *p2s,
                                   i2d_of_void *k2d,
                                   struct key2any_ctx_st *ctx)
{
	GOSTPROV_PRINTF("GOSTPROV provider: key_to_spki_pem_pub_bio\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int prepare_gostprov_params(const void *gost_xkey, int nid, int save,
                             void **pstr, int *pstrtype)
{
	GOSTPROV_PRINTF("GOSTPROV provider: prepare_gostprov_params\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}


static int gostprov_spki_pub_to_der(const void *vxkey, unsigned char **pder)
{
	GOSTPROV_PRINTF("GOSTPROV provider: gostprov_spki_pub_to_der called\n");

	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_pki_priv_to_der(const void *vxkey, unsigned char **pder)
{
	GOSTPROV_PRINTF("GOSTPROV provider: gostprov_pki_priv_to_der\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

# define gostprov_epki_priv_to_der gostprov_pki_priv_to_der

# define gostprov_check_key_type     NULL

// OQS provider uses NIDs generated at load time as EVP_type identifiers
// so initially this must be 0 and set to a real value by OBJ_sn2nid later
# define gost2012_256_evp_type       "gost2012_256"
# define gost2012_256_input_type      "gost2012_256"
# define gost2012_256_pem_type        "gost2012_256"

//# define dilithium2_evp_type       0
//# define dilithium2_input_type      "dilithium2"
//# define dilithium2_pem_type        "dilithium2"
//# define p256_dilithium2_evp_type       0
//# define p256_dilithium2_input_type      "p256_dilithium2"
//# define p256_dilithium2_pem_type        "p256_dilithium2"

/* ---------------------------------------------------------------------- */

static OSSL_FUNC_decoder_newctx_fn key2any_newctx;
static OSSL_FUNC_decoder_freectx_fn key2any_freectx;

static void *key2any_newctx(void *provctx)
{
    struct key2any_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    GOSTPROV_PRINTF("GOSTPROV provider: key2any_newctx called\n");

    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->save_parameters = 1;
    }

    return ctx;
}

static void key2any_freectx(void *vctx)
{
    struct key2any_ctx_st *ctx = vctx;

    GOSTPROV_PRINTF("GOSTPROV provider: key2any_freectx called\n");

    EVP_CIPHER_free(ctx->cipher);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *key2any_settable_ctx_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    GOSTPROV_PRINTF("GOSTPROV provider: key2any_settable_ctx_params called\n");

    return settables;
}

static int key2any_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct key2any_ctx_st *ctx = vctx;
    OSSL_LIB_CTX *libctx = ctx->provctx->libctx;
    const OSSL_PARAM *cipherp =
        OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    const OSSL_PARAM *propsp =
        OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
    const OSSL_PARAM *save_paramsp =
        OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_SAVE_PARAMETERS);

    GOSTPROV_PRINTF("GOSTPROV provider: key2any_set_ctx_params called\n");

    if (cipherp != NULL) {
        const char *ciphername = NULL;
        const char *props = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(cipherp, &ciphername))
            return 0;
        GOSTPROV_PRINTF2(" setting cipher: %s\n", ciphername);
        if (propsp != NULL && !OSSL_PARAM_get_utf8_string_ptr(propsp, &props))
            return 0;

        EVP_CIPHER_free(ctx->cipher);
        ctx->cipher = NULL;
        ctx->cipher_intent = ciphername != NULL;
        if (ciphername != NULL
            && ((ctx->cipher =
                 EVP_CIPHER_fetch(libctx, ciphername, props)) == NULL)) {
            return 0;
	}
    }

    if (save_paramsp != NULL) {
        if (!OSSL_PARAM_get_int(save_paramsp, &ctx->save_parameters)) {
            return 0;
	}
    }
    GOSTPROV_PRINTF2(" cipher set to %p: \n", ctx->cipher);
    return 1;
}

static int key2any_check_selection(int selection, int selection_mask)
{
	GOSTPROV_PRINTF("GOSTPROV provider: key2any_check_selection\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int key2any_encode(struct key2any_ctx_st *ctx, OSSL_CORE_BIO *cout,
                          const void *key, const char* typestr, const char *pemname,
                          key_to_der_fn *writer,
                          OSSL_PASSPHRASE_CALLBACK *pwcb, void *pwcbarg,
                          key_to_paramstring_fn *key2paramstring,
                          i2d_of_void *key2der)
{
	GOSTPROV_PRINTF("GOSTPROV provider: key2any_encode\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

#define DO_PRIVATE_KEY_selection_mask OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define DO_PRIVATE_KEY(impl, type, kind, output)                            \
    if ((selection & DO_PRIVATE_KEY_selection_mask) != 0)                   \
        return key2any_encode(ctx, cout, key, impl##_pem_type,              \
                              impl##_pem_type " PRIVATE KEY",               \
                              key_to_##kind##_##output##_priv_bio,          \
                              cb, cbarg, prepare_##type##_params,           \
                              type##_##kind##_priv_to_der);

#define DO_PUBLIC_KEY_selection_mask OSSL_KEYMGMT_SELECT_PUBLIC_KEY
#define DO_PUBLIC_KEY(impl, type, kind, output)                             \
    if ((selection & DO_PUBLIC_KEY_selection_mask) != 0)                    \
        return key2any_encode(ctx, cout, key, impl##_pem_type,              \
                              impl##_pem_type " PUBLIC KEY",                \
                              key_to_##kind##_##output##_pub_bio,           \
                              cb, cbarg, prepare_##type##_params,           \
                              type##_##kind##_pub_to_der);

#define DO_PARAMETERS_selection_mask OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
#define DO_PARAMETERS(impl, type, kind, output)                             \
    if ((selection & DO_PARAMETERS_selection_mask) != 0)                    \
        return key2any_encode(ctx, cout, key, impl##_pem_type,              \
                              impl##_pem_type " PARAMETERS",                \
                              key_to_##kind##_##output##_param_bio,         \
                              NULL, NULL, NULL,                             \
                              type##_##kind##_params_to_der);

/*-
 * Implement the kinds of output structure that can be produced.  They are
 * referred to by name, and for each name, the following macros are defined
 * (braces not included):
 *
 * DO_{kind}_selection_mask
 *
 *      A mask of selection bits that must not be zero.  This is used as a
 *      selection criterion for each implementation.
 *      This mask must never be zero.
 *
 * DO_{kind}
 *
 *      The performing macro.  It must use the DO_ macros defined above,
 *      always in this order:
 *
 *      - DO_PRIVATE_KEY
 *      - DO_PUBLIC_KEY
 *      - DO_PARAMETERS
 *
 *      Any of those may be omitted, but the relative order must still be
 *      the same.
 */

/*
 * PKCS#8 defines two structures for private keys only:
 * - PrivateKeyInfo             (raw unencrypted form)
 * - EncryptedPrivateKeyInfo    (encrypted wrapping)
 *
 * To allow a certain amount of flexibility, we allow the routines
 * for PrivateKeyInfo to also produce EncryptedPrivateKeyInfo if a
 * passphrase callback has been passed to them.
 */
#define DO_PrivateKeyInfo_selection_mask DO_PRIVATE_KEY_selection_mask
#define DO_PrivateKeyInfo(impl, type, output)                               \
    DO_PRIVATE_KEY(impl, type, pki, output)

#define DO_EncryptedPrivateKeyInfo_selection_mask DO_PRIVATE_KEY_selection_mask
#define DO_EncryptedPrivateKeyInfo(impl, type, output)                      \
    DO_PRIVATE_KEY(impl, type, epki, output)

/* SubjectPublicKeyInfo is a structure for public keys only */
#define DO_SubjectPublicKeyInfo_selection_mask DO_PUBLIC_KEY_selection_mask
#define DO_SubjectPublicKeyInfo(impl, type, output)                         \
    DO_PUBLIC_KEY(impl, type, spki, output)

/*
 * "type-specific" is a uniform name for key type specific output for private
 * and public keys as well as key parameters.  This is used internally in
 * libcrypto so it doesn't have to have special knowledge about select key
 * types, but also when no better name has been found.  If there are more
 * expressive DO_ names above, those are preferred.
 *
 * Three forms exist:
 *
 * - type_specific_keypair              Only supports private and public key
 * - type_specific_params               Only supports parameters
 * - type_specific                      Supports all parts of an EVP_PKEY
 * - type_specific_no_pub               Supports all parts of an EVP_PKEY
 *                                      except public key
 */
#define DO_type_specific_params_selection_mask DO_PARAMETERS_selection_mask
#define DO_type_specific_params(impl, type, output)                         \
    DO_PARAMETERS(impl, type, type_specific, output)
#define DO_type_specific_keypair_selection_mask                             \
    ( DO_PRIVATE_KEY_selection_mask | DO_PUBLIC_KEY_selection_mask )
#define DO_type_specific_keypair(impl, type, output)                        \
    DO_PRIVATE_KEY(impl, type, type_specific, output)                       \
    DO_PUBLIC_KEY(impl, type, type_specific, output)
#define DO_type_specific_selection_mask                                     \
    ( DO_type_specific_keypair_selection_mask                               \
      | DO_type_specific_params_selection_mask )
#define DO_type_specific(impl, type, output)                                \
    DO_type_specific_keypair(impl, type, output)                            \
    DO_type_specific_params(impl, type, output)
#define DO_type_specific_no_pub_selection_mask \
    ( DO_PRIVATE_KEY_selection_mask |  DO_PARAMETERS_selection_mask)
#define DO_type_specific_no_pub(impl, type, output)                         \
    DO_PRIVATE_KEY(impl, type, type_specific, output)                       \
    DO_type_specific_params(impl, type, output)

/*
 * MAKE_ENCODER is the single driver for creating OSSL_DISPATCH tables.
 * It takes the following arguments:
 *
 * impl         This is the key type name that's being implemented.
 * type         This is the type name for the set of functions that implement
 *              the key type.  For example, ed25519, ed448, x25519 and x448
 *              are all implemented with the exact same set of functions.
 * kind         What kind of support to implement.  These translate into
 *              the DO_##kind macros above.
 * output       The output type to implement.  may be der or pem.
 *
 * The resulting OSSL_DISPATCH array gets the following name (expressed in
 * C preprocessor terms) from those arguments:
 *
 * gostprov_##impl##_to_##kind##_##output##_encoder_functions
 */
#define MAKE_ENCODER(impl, type, kind, output)                    \
    static OSSL_FUNC_encoder_import_object_fn                               \
    impl##_to_##kind##_##output##_import_object;                            \
    static OSSL_FUNC_encoder_free_object_fn                                 \
    impl##_to_##kind##_##output##_free_object;                              \
    static OSSL_FUNC_encoder_encode_fn                                      \
    impl##_to_##kind##_##output##_encode;                                   \
                                                                            \
    static void *                                                           \
    impl##_to_##kind##_##output##_import_object(void *vctx, int selection,  \
                                                const OSSL_PARAM params[])  \
    {                                                                       \
        struct key2any_ctx_st *ctx = vctx;                                  \
                                                                            \
        GOSTPROV_PRINTF("GOSTPROV provider: _import_object called\n"); \
        return gostprov_import_key(gostprov_##impl##_keymgmt_functions,        \
                                    ctx->provctx, selection, params);       \
    }                                                                       \
    static void impl##_to_##kind##_##output##_free_object(void *key)        \
    {                                                                       \
        GOSTPROV_PRINTF("GOSTPROV provider: _free_object called\n"); \
        gostprov_free_key(gostprov_##impl##_keymgmt_functions, key);           \
    }                                                                       \
    static int impl##_to_##kind##_##output##_does_selection(void *ctx,      \
                                                            int selection)  \
    {                                                                       \
        GOSTPROV_PRINTF("GOSTPROV provider: _does_selection called\n"); \
        return key2any_check_selection(selection,                           \
                                       DO_##kind##_selection_mask);         \
    }                                                                       \
    static int                                                              \
    impl##_to_##kind##_##output##_encode(void *ctx, OSSL_CORE_BIO *cout,    \
                                         const void *key,                   \
                                         const OSSL_PARAM key_abstract[],   \
                                         int selection,                     \
                                         OSSL_PASSPHRASE_CALLBACK *cb,      \
                                         void *cbarg)                       \
    {                                                                       \
        /* We don't deal with abstract objects */                           \
        GOSTPROV_PRINTF("GOSTPROV provider: _encode called\n"); \
        if (key_abstract != NULL) {                                         \
            ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);         \
            return 0;                                                       \
        }                                                                   \
        DO_##kind(impl, type, output)                                       \
                                                                            \
        ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);             \
        return 0;                                                           \
    }                                                                       \
    const OSSL_DISPATCH                                                     \
    gostprov_##impl##_to_##kind##_##output##_encoder_functions[] = {            \
        { OSSL_FUNC_ENCODER_NEWCTX,                                         \
          (void (*)(void))key2any_newctx },                                 \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
          (void (*)(void))key2any_freectx },                                \
        { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
          (void (*)(void))key2any_settable_ctx_params },                    \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
          (void (*)(void))key2any_set_ctx_params },                         \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                                 \
          (void (*)(void))impl##_to_##kind##_##output##_does_selection },   \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
          (void (*)(void))impl##_to_##kind##_##output##_import_object },    \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
          (void (*)(void))impl##_to_##kind##_##output##_free_object },      \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
          (void (*)(void))impl##_to_##kind##_##output##_encode },           \
        { 0, NULL }                                                         \
    }


/* ---------------------------------------------------------------------- */

/* steal from openssl/providers/implementations/encode_decode/encode_key2text.c */

#define LABELED_BUF_PRINT_WIDTH    15

static int print_labeled_buf(BIO *out, const char *label,
                             const unsigned char *buf, size_t buflen)
{
    size_t i;

    if (BIO_printf(out, "%s\n", label) <= 0)
        return 0;

    for (i = 0; i < buflen; i++) {
        if ((i % LABELED_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_printf(out, "\n") <= 0)
                return 0;
            if (BIO_printf(out, "    ") <= 0)
                return 0;
        }

        if (BIO_printf(out, "%02x%s", buf[i],
                                 (i == buflen - 1) ? "" : ":") <= 0)
            return 0;
    }
    if (BIO_printf(out, "\n") <= 0)
        return 0;

    return 1;
}

static int gostprov_to_text(BIO *out, const void *key, int selection)
{
	GOSTPROV_PRINTF("GOSTPROV provider: gostprov_to_text\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static void *key2text_newctx(void *provctx)
{
    return provctx;
}

static void key2text_freectx(ossl_unused void *vctx)
{
}

static int key2text_encode(void *vctx, const void *key, int selection,
                           OSSL_CORE_BIO *cout,
                           int (*key2text)(BIO *out, const void *key,
                                           int selection),
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	GOSTPROV_PRINTF("GOSTPROV provider: key2text_encode\n");
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

#define MAKE_TEXT_ENCODER(impl)                                         \
    static OSSL_FUNC_encoder_import_object_fn                           \
    impl##2text_import_object;                                          \
    static OSSL_FUNC_encoder_free_object_fn                             \
    impl##2text_free_object;                                            \
    static OSSL_FUNC_encoder_encode_fn impl##2text_encode;              \
                                                                        \
    static void *impl##2text_import_object(void *ctx, int selection,    \
                                           const OSSL_PARAM params[])   \
    {                                                                   \
        return gostprov_import_key(gostprov_##impl##_keymgmt_functions,      \
                                    ctx, selection, params);            \
    }                                                                   \
    static void impl##2text_free_object(void *key)                      \
    {                                                                   \
        gostprov_free_key(gostprov_##impl##_keymgmt_functions, key);         \
    }                                                                   \
    static int impl##2text_encode(void *vctx, OSSL_CORE_BIO *cout,      \
                                  const void *key,                      \
                                  const OSSL_PARAM key_abstract[],      \
                                  int selection,                        \
                                  OSSL_PASSPHRASE_CALLBACK *cb,         \
                                  void *cbarg)                          \
    {                                                                   \
        /* We don't deal with abstract objects */                       \
        if (key_abstract != NULL) {                                     \
            ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);     \
            return 0;                                                   \
        }                                                               \
        return key2text_encode(vctx, key, selection, cout,              \
                               gostprov_to_text, cb, cbarg);                \
    }                                                                   \
    const OSSL_DISPATCH gostprov_##impl##_to_text_encoder_functions[] = {    \
        { OSSL_FUNC_ENCODER_NEWCTX,                                     \
          (void (*)(void))key2text_newctx },                            \
        { OSSL_FUNC_ENCODER_FREECTX,                                    \
          (void (*)(void))key2text_freectx },                           \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                              \
          (void (*)(void))impl##2text_import_object },                  \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                \
          (void (*)(void))impl##2text_free_object },                    \
        { OSSL_FUNC_ENCODER_ENCODE,                                     \
          (void (*)(void))impl##2text_encode },                         \
        { 0, NULL }                                                     \
    }

/*
 * Replacements for i2d_{TYPE}PrivateKey, i2d_{TYPE}PublicKey,
 * i2d_{TYPE}params, as they exist.
 */

/*
 * PKCS#8 and SubjectPublicKeyInfo support.  This may duplicate some of the
 * implementations specified above, but are more specific.
 * The SubjectPublicKeyInfo implementations also replace the
 * PEM_write_bio_{TYPE}_PUBKEY functions.
 * For PEM, these are expected to be used by PEM_write_bio_PrivateKey(),
 * PEM_write_bio_PUBKEY() and PEM_write_bio_Parameters().
 */

MAKE_ENCODER(gost2012_256, gostprov, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(gost2012_256, gostprov, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(gost2012_256, gostprov, PrivateKeyInfo, der);
MAKE_ENCODER(gost2012_256, gostprov, PrivateKeyInfo, pem);
MAKE_ENCODER(gost2012_256, gostprov, SubjectPublicKeyInfo, der);
MAKE_ENCODER(gost2012_256, gostprov, SubjectPublicKeyInfo, pem);
MAKE_TEXT_ENCODER(gost2012_256);


