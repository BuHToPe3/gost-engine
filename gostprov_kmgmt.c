// Code inspired by OpenSSL common provider and OQS provider code

#include <assert.h>

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "openssl/param_build.h"
#include "gost_prov.h"

int gostprov_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key,
                                      const unsigned char *data,
                                      size_t data_len)
{
    if (bld != NULL)
        return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

    p = OSSL_PARAM_locate(p, key);
    if (p != NULL)
        return OSSL_PARAM_set_octet_string(p, data, data_len);
    return 1;
}

static OSSL_FUNC_keymgmt_gen_cleanup_fn gostprov_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn gostprov_load;
static OSSL_FUNC_keymgmt_get_params_fn gostprov_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn gostprov_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn gostprov_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn gostprov_settable_params;
static OSSL_FUNC_keymgmt_has_fn gostprov_has;
static OSSL_FUNC_keymgmt_match_fn gostprov_match;
static OSSL_FUNC_keymgmt_import_fn gostprov_import;
static OSSL_FUNC_keymgmt_import_types_fn gostprov_imexport_types;
static OSSL_FUNC_keymgmt_export_fn gostprov_export;
static OSSL_FUNC_keymgmt_export_types_fn gostprov_imexport_types;

struct gostprov_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    char *gost_name;
    char *tls_name;
    int primitive;
    int selection;
    int bit_security;
    int alg_idx;
};

static int gostprov_has(const void *keydata, int selection)
{
    const GOSTPROV_KEY *key = keydata;
    int ok = 0;

    GOSTPROV_PRINTF("GOSTPROV: gostprov_has called\n");
    if (key != NULL) {
        /*
         * OQSX keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->privkey != NULL;
    }
    if (!ok) GOSTPROV_PRINTF2("GOSTPROV: has returning FALSE on selection %2x\n", selection);
    return ok;
}

/*
 * Key matching has a problem in OQS world: OpenSSL assumes all keys to (also)
 * contain public key material (https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_eq.html).
 * This is not the case with decoded private keys: Not all algorithms permit re-creating
 * public key material from private keys (https://github.com/PQClean/PQClean/issues/415#issuecomment-910377682).
 * Thus we implement the following logic:
 * 1) Private keys are matched binary if available in both keys; only one key having private key material 
 *    will be considered a mismatch
 * 2) Public keys are matched binary if available in both keys; only one key having public key material
 *    will NOT be considered a mismatch if both private keys are present and match: The latter logic will
 *    only be triggered if domain parameter matching is requested to distinguish between a pure-play
 *    public key match/test and one checking OpenSSL-type "EVP-PKEY-equality". This is possible as domain
 *    parameters don't really play a role in OQS, so we consider them as a proxy for private key matching.
 */

static int gostprov_match(const void *keydata1, const void *keydata2, int selection)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

static int gostprov_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    GOSTPROV_KEY *key = keydata;
    int ok = 0;

    GOSTPROV_PRINTF("GOSTPROV: import called \n");
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
        return ok;
    }

    if (((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) &&
        (gostprov_key_fromdata(key, params, 1)))
        ok = 1;
    return ok;
}

int gostprov_key_to_params(const GOSTPROV_KEY *key, OSSL_PARAM_BLD *tmpl,
                  OSSL_PARAM params[], int include_private)
{
    int ret = 0;

    if (key == NULL)
        return 0;

    if (key->pubkey != NULL) {
        OSSL_PARAM *p = NULL;

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (   key->pubkeylen == 0 
                || !gostprov_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PUB_KEY,
                                                      key->pubkey, key->pubkeylen))
                goto err;
        }
    }
    if (key->privkey != NULL && include_private) {
        OSSL_PARAM *p = NULL;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key. Conceptually. OQS is not production strength
         * so does not care. TBD.
         *
         */

        if (tmpl == NULL) {
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }

        if (p != NULL || tmpl != NULL) {
            if (   key->privkeylen == 0 
                || !gostprov_param_build_set_octet_string(tmpl, p,
                                                      OSSL_PKEY_PARAM_PRIV_KEY,
                                                      key->privkey, key->privkeylen))
                goto err;
        }
    }
    ret = 1;
 err:
    return ret;
}

static int gostprov_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    GOSTPROV_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    //OSSL_PARAM *p;
    int ok = 1;

    GOSTPROV_PRINTF("GOSTPROV: gostprov_export called\n");

    /*
     * In this implementation, only public and private keys can be exported, nothing else
     */
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
        return 0;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && gostprov_key_to_params(key, tmpl, NULL, include_private);
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        ok = 0;
        goto err;
    }

    ok = ok & param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ok;
}

#define GOSTPROV_KEY_TYPES()                                                        \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),                     \
OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM gostprov_key_types[] = {
    GOSTPROV_KEY_TYPES(),
    OSSL_PARAM_END
};
static const OSSL_PARAM *gostprov_imexport_types(int selection)
{
    GOSTPROV_PRINTF("GOSTPROV: imexport called\n");
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return gostprov_key_types;
    return NULL;
}

// must handle param requests for KEM and SIG keys...
static int gostprov_get_params(void *key, OSSL_PARAM params[])
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

static const OSSL_PARAM gostprov_x_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    GOSTPROV_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gostprov_gettable_params(void *provctx)
{
    GOSTPROV_PRINTF("GOSTPROV: gettable_params called\n");
    return gostprov_x_gettable_params;
}

static int set_property_query(GOSTPROV_KEY *gostxkey, const char *propq)
{
    OPENSSL_free(gostxkey->propq);
    gostxkey->propq = NULL;
    GOSTPROV_PRINTF("GOSTPROV: property_query called\n");
    if (propq != NULL) {
        gostxkey->propq = OPENSSL_strdup(propq);
        if (gostxkey->propq == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    return 1;
}

static int gostprov_set_params(void *key, const OSSL_PARAM params[])
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return -1;
}

static const OSSL_PARAM gostprov_x_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gostprov_settable_params(void *provctx)
{
    GOSTPROV_PRINTF("GOSTPROV: settable_params called\n");
    return gostprov_x_settable_params;
}

static void *gostprov_gen_init(void *provctx, int selection, char* gost_name, char* tls_name, int primitive, int bit_security, int alg_idx)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
	return NULL;
}

static void *gostprov_genkey(struct gostprov_gen_ctx *gctx)
{
    GOSTPROV_KEY *key;

    GOSTPROV_PRINTF3("GOSTPROV: gen called for %s (%s)\n", gctx->gost_name, gctx->tls_name);
    if (gctx == NULL)
        return NULL;
    if ((key = gostprov_key_new(gctx->libctx, gctx->gost_name, gctx->tls_name, gctx->primitive, gctx->propq, gctx->bit_security, gctx->alg_idx)) == NULL) {
	GOSTPROV_PRINTF2("GOSTPROV: Error generating key for %s\n", gctx->tls_name);
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (gostprov_key_gen(key)) {
       ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
       return NULL;
    }
    return key;
}

static void *gostprov_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct gostprov_gen_ctx *gctx = genctx;

    GOSTPROV_PRINTF("GOSTPROV: gen called\n");

    return gostprov_genkey(gctx);
}

static void gostprov_gen_cleanup(void *genctx)
{
    struct gostprov_gen_ctx *gctx = genctx;

    GOSTPROV_PRINTF("GOSTPROV: gen_cleanup called\n");
    OPENSSL_free(gctx->gost_name);
    OPENSSL_free(gctx->tls_name);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

void *gostprov_load(const void *reference, size_t reference_sz)
{
    GOSTPROV_KEY *key = NULL;

    GOSTPROV_PRINTF("GOSTPROV: load called\n");
    if (reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(GOSTPROV_KEY **)reference;
        /* We grabbed, so we detach it */
        *(GOSTPROV_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static const OSSL_PARAM *gostprov_gen_settable_params(void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static int gostprov_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct gostprov_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    GOSTPROV_PRINTF("GOSTPROV: gen_set_params called\n");
    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *algname = (char*)p->data;

        OPENSSL_free(gctx->tls_name);
        gctx->tls_name = OPENSSL_strdup(algname);
    }
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}


static void *gost2012_256_new_key(void *provctx)
{
    return gostprov_key_new(GOSTPROV_LIBCTX_OF(provctx), "GOST2012_256", "gost2012_256", KEY_TYPE_SIG, NULL, 256, 0);
}

static void *gost2012_256_gen_init(void *provctx, int selection)
{
    return gostprov_gen_init(provctx, selection, "GOST2012_256", "gost2012_256", 0, 256, 0);
}

static void *hash_with_sign12_256_new_key(void *provctx)
{
    return gostprov_key_new(GOSTPROV_LIBCTX_OF(provctx), "GOST2012_256", "hash_with_sign12_256", KEY_TYPE_SIG, NULL, 256, 0);
}

static void *hash_with_sign12_256_gen_init(void *provctx, int selection)
{
    return gostprov_gen_init(provctx, selection, "GOST2012_256", "hash_with_sign12_256", 0, 256, 0);
}


#define MAKE_SIG_KEYMGMT_FUNCTIONS(alg) \
\
    const OSSL_DISPATCH gostprov_##alg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))alg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gostprov_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))gostprov_get_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))gostprov_settable_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))gostprov_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))gostprov_set_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gostprov_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gostprov_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gostprov_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gostprov_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))alg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gostprov_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gostprov_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gostprov_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))gostprov_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gostprov_load }, \
        { 0, NULL } \
    };

#define MAKE_KEM_KEYMGMT_FUNCTIONS(tokalg, tokgostalg, bit_security) \
\
    static void *tokalg##_new_key(void *provctx) \
    { \
        return gostprov_key_new(GOSTPROV_LIBCTX_OF(provctx), tokgostalg, "" #tokalg "", KEY_TYPE_KEM, NULL, bit_security, -1); \
    }                                                 \
                                                      \
    static void *tokalg##_gen_init(void *provctx, int selection) \
    { \
        return gostprov_gen_init(provctx, selection, tokgostalg, "" #tokalg "", KEY_TYPE_KEM, bit_security, -1); \
    }                                                 \
                                                      \
    const OSSL_DISPATCH gostprov_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tokalg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gostprov_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))gostprov_get_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))gostprov_settable_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))gostprov_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))gostprov_set_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gostprov_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gostprov_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gostprov_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gostprov_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gostprov_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gostprov_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gostprov_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))gostprov_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gostprov_load }, \
        { 0, NULL } \
    };

#define MAKE_KEM_ECP_KEYMGMT_FUNCTIONS(tokalg, tokgostalg, bit_security) \
                                                      \
    static void *ecp_##tokalg##_new_key(void *provctx) \
    { \
        return gostprov_key_new(GOSTPROV_LIBCTX_OF(provctx), tokgostalg, "" #tokalg "", KEY_TYPE_ECP_HYB_KEM, NULL, bit_security, -1); \
    } \
                                                      \
    static void *ecp_##tokalg##_gen_init(void *provctx, int selection) \
    { \
        return gostprov_gen_init(provctx, selection, tokgostalg, "" #tokalg "", KEY_TYPE_ECP_HYB_KEM, bit_security, -1); \
    } \
                                                      \
    const OSSL_DISPATCH gostprov_ecp_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecp_##tokalg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gostprov_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))gostprov_get_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))gostprov_settable_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))gostprov_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))gostprov_set_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gostprov_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gostprov_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gostprov_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gostprov_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecp_##tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gostprov_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gostprov_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gostprov_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))gostprov_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gostprov_load }, \
        { 0, NULL } \
    };

#define MAKE_KEM_ECX_KEYMGMT_FUNCTIONS(tokalg, tokgostalg, bit_security) \
    static void *ecx_##tokalg##_new_key(void *provctx) \
    { \
        return gostprov_key_new(GOSTPROV_LIBCTX_OF(provctx), tokgostalg, "" #tokalg "", KEY_TYPE_ECX_HYB_KEM, NULL, bit_security, -1); \
    } \
                                                      \
    static void *ecx_##tokalg##_gen_init(void *provctx, int selection) \
    { \
        return gostprov_gen_init(provctx, selection, tokgostalg, "" #tokalg "", KEY_TYPE_ECX_HYB_KEM, bit_security, -1); \
    } \
                                                      \
    const OSSL_DISPATCH gostprov_ecx_##tokalg##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ecx_##tokalg##_new_key }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))gostprov_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))gostprov_get_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))gostprov_settable_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))gostprov_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))gostprov_set_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))gostprov_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))gostprov_match }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))gostprov_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))gostprov_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))gostprov_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ecx_##tokalg##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gostprov_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gostprov_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gostprov_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))gostprov_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))gostprov_load }, \
        { 0, NULL } \
    };

MAKE_SIG_KEYMGMT_FUNCTIONS(gost2012_256)
MAKE_SIG_KEYMGMT_FUNCTIONS(hash_with_sign12_256)

