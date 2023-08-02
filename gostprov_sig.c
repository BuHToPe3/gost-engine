// Code inspired by OpenSSL common provider and OQS provider code

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "gost_prov.h"

// TBD: Review what we really need/want: For now go with OSSL settings:
#define OSSL_MAX_NAME_SIZE 50
#define OSSL_MAX_PROPQUERY_SIZE     256 /* Property query strings */

static OSSL_FUNC_signature_newctx_fn gostprov_sig_newctx;
static OSSL_FUNC_signature_sign_init_fn gostprov_sig_sign_init;
static OSSL_FUNC_signature_verify_init_fn gostprov_sig_verify_init;
static OSSL_FUNC_signature_sign_fn gostprov_sig_sign;
static OSSL_FUNC_signature_verify_fn gostprov_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn gostprov_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn gostprov_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn gostprov_sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn gostprov_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn gostprov_sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn gostprov_sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn gostprov_sig_freectx;
static OSSL_FUNC_signature_dupctx_fn gostprov_sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn gostprov_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn gostprov_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn gostprov_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn gostprov_sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn gostprov_sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn gostprov_sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn gostprov_sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn gostprov_sig_settable_ctx_md_params;

// OIDS:
static int get_aid(unsigned char** oidbuf, const char *tls_name) {
   X509_ALGOR *algor = X509_ALGOR_new();
   int aidlen = 0;

   X509_ALGOR_set0(algor, OBJ_txt2obj(tls_name, 0), V_ASN1_UNDEF, NULL);

   aidlen = i2d_X509_ALGOR(algor, oidbuf); 
   X509_ALGOR_free(algor);
   return(aidlen);
}

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    GOSTPROV_KEY *sig;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;
    // for collecting data if no MD is active:
    unsigned char* mddata;
    int operation;
} GOSTPROV_GOSTSIG_CTX;

static void *gostprov_sig_newctx(void *provctx, const char *propq)
{
    GOSTPROV_GOSTSIG_CTX *pgostprov_sigctx;

    GOSTPROV_PRINTF2("GOSTPROV provider: newctx called with propq %s\n", propq);

    pgostprov_sigctx = OPENSSL_zalloc(sizeof(GOSTPROV_GOSTSIG_CTX));
    if (pgostprov_sigctx == NULL)
        return NULL;

    pgostprov_sigctx->libctx = ((PROV_CTX*)provctx)->libctx;
    if (propq != NULL && (pgostprov_sigctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(pgostprov_sigctx);
        pgostprov_sigctx = NULL;
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    }
	
    return pgostprov_sigctx;
}

static int gostprov_sig_setup_md(GOSTPROV_GOSTSIG_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    GOSTPROV_PRINTF3("GOSTPROV provider: setup_md called for MD %s (alg %s)\n", mdname, ctx->sig->tls_name);
    if (mdprops == NULL)
        mdprops = ctx->propq;

    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);

        if ((md == NULL)||(EVP_MD_nid(md)==NID_undef)) {
            if (md == NULL)
                ERR_raise_data(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED,
                               "%s could not be fetched", mdname);
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_CTX_free(ctx->mdctx);
		ctx->mdctx = NULL;
        EVP_MD_free(ctx->md);
		ctx->md = NULL;

        if (ctx->aid) 
            OPENSSL_free(ctx->aid);
        ctx->aid = NULL; // ensure next function allocates memory
        ctx->aid_len = get_aid(&(ctx->aid), ctx->sig->tls_name);

        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }
    return 1;
}

static int gostprov_sig_signverify_init(void *vpgostprov_sigctx, void *vgostsig, int operation)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_sig_sign_init(void *vpgostprov_sigctx, void *vgostprov_sig, const OSSL_PARAM params[])
{
    GOSTPROV_PRINTF("GOSTPROV provider: sign_init called\n");
    return gostprov_sig_signverify_init(vpgostprov_sigctx, vgostprov_sig, EVP_PKEY_OP_SIGN);
}

static int gostprov_sig_verify_init(void *vpgostprov_sigctx, void *vgostprov_sig, const OSSL_PARAM params[])
{
    GOSTPROV_PRINTF("GOSTPROV provider: verify_init called\n");
    return gostprov_sig_signverify_init(vpgostprov_sigctx, vgostprov_sig, EVP_PKEY_OP_VERIFY);
}

/* On entry to this function, data to be signed (tbs) might have been hashed already:
 * this would be the case if pgostprov_sigctx->mdctx != NULL; if that is NULL, we have to hash
 * in case of hybrid signatures
 */
static int gostprov_sig_sign(void *vpgostprov_sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_sig_verify(void *vpgostprov_sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_sig_digest_signverify_init(void *vpgostprov_sigctx, const char *mdname,
                                      void *vgostprov_sig, int operation)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static int gostprov_sig_digest_sign_init(void *vpgostprov_sigctx, const char *mdname,
                                      void *vgostprov_sig, const OSSL_PARAM params[])
{
    GOSTPROV_PRINTF("GOSTPROV provider: digest_sign_init called\n");
    return gostprov_sig_digest_signverify_init(vpgostprov_sigctx, mdname, vgostprov_sig, EVP_PKEY_OP_SIGN);
}

static int gostprov_sig_digest_verify_init(void *vpgostprov_sigctx, const char *mdname, void *vgostprov_sig, const OSSL_PARAM params[])
{
    GOSTPROV_PRINTF("GOSTPROV provider: sig_digest_verify called\n");
    return gostprov_sig_digest_signverify_init(vpgostprov_sigctx, mdname, vgostprov_sig, EVP_PKEY_OP_VERIFY);
}

int gostprov_sig_digest_signverify_update(void *vpgostprov_sigctx, const unsigned char *data,
                                 size_t datalen)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

int gostprov_sig_digest_sign_final(void *vpgostprov_sigctx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}


int gostprov_sig_digest_verify_final(void *vpgostprov_sigctx, const unsigned char *sig,
                            size_t siglen)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static void gostprov_sig_freectx(void *vpgostprov_sigctx)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    //return -1;
}

static void *gostprov_sig_dupctx(void *vpgostprov_sigctx)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return NULL;
}

static int gostprov_sig_get_ctx_params(void *vpgostprov_sigctx, OSSL_PARAM *params)
{
    ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gostprov_sig_gettable_ctx_params(ossl_unused void *vpgostprov_sigctx, ossl_unused void *vctx)
{
    GOSTPROV_PRINTF("GOSTPROV provider: gettable_ctx_params called\n");
    return known_gettable_ctx_params;
}
static int gostprov_sig_set_ctx_params(void *vpgostprov_sigctx, const OSSL_PARAM params[])
{
	ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
    return -1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gostprov_sig_settable_ctx_params(ossl_unused void *vpsm2ctx,
                                                     ossl_unused void *provctx)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     * NOTE: Ideally we would check poqs_sigctx->flag_allow_md, but this is
     * problematic because there is no nice way of passing the
     * PROV_OQSSIG_CTX down to this function...
     * Because we have API's that dont know about their parent..
     * e.g: EVP_SIGNATURE_gettable_ctx_params(const EVP_SIGNATURE *sig).
     * We could pass NULL for that case (but then how useful is the check?).
     */
    GOSTPROV_PRINTF("GOSTPROV provider: settable_ctx_params called\n");
    return known_settable_ctx_params;
}

static int gostprov_sig_get_ctx_md_params(void *vpgostprov_sigctx, OSSL_PARAM *params)
{
    GOSTPROV_GOSTSIG_CTX *pgostprov_sigctx = (GOSTPROV_GOSTSIG_CTX *)vpgostprov_sigctx;

    GOSTPROV_PRINTF("GOSTPROV provider: get_ctx_md_params called\n");
    if (pgostprov_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(pgostprov_sigctx->mdctx, params);
}

static const OSSL_PARAM *gostprov_sig_gettable_ctx_md_params(void *vpgostprov_sigctx)
{
    GOSTPROV_GOSTSIG_CTX *pgostprov_sigctx = (GOSTPROV_GOSTSIG_CTX *)vpgostprov_sigctx;

    GOSTPROV_PRINTF("GOSTPROV provider: gettable_ctx_md_params called\n");
    if (pgostprov_sigctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(pgostprov_sigctx->md);
}

static int gostprov_sig_set_ctx_md_params(void *vpgostprov_sigctx, const OSSL_PARAM params[])
{
    GOSTPROV_GOSTSIG_CTX *pgostprov_sigctx = (GOSTPROV_GOSTSIG_CTX *)vpgostprov_sigctx;

    GOSTPROV_PRINTF("GOSTPROV provider: set_ctx_md_params called\n");
    if (pgostprov_sigctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(pgostprov_sigctx->mdctx, params);
}

static const OSSL_PARAM *gostprov_sig_settable_ctx_md_params(void *vpgostprov_sigctx)
{
    GOSTPROV_GOSTSIG_CTX *pgostprov_sigctx = (GOSTPROV_GOSTSIG_CTX *)vpgostprov_sigctx;

    if (pgostprov_sigctx->md == NULL)
        return 0;

    GOSTPROV_PRINTF("GOSTPROV provider: settable_ctx_md_params called\n");
    return EVP_MD_settable_ctx_params(pgostprov_sigctx->md);
}

const OSSL_DISPATCH gostprov_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))gostprov_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))gostprov_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))gostprov_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))gostprov_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))gostprov_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))gostprov_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))gostprov_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))gostprov_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))gostprov_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))gostprov_sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))gostprov_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))gostprov_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))gostprov_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))gostprov_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))gostprov_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))gostprov_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))gostprov_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))gostprov_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))gostprov_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))gostprov_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))gostprov_sig_settable_ctx_md_params },
    { 0, NULL }
};
