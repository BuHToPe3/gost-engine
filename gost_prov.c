/**********************************************************************
 *                 gost_prov.c - The provider itself                  *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "prov/err.h"           /* libprov err functions */
#include "gostprov_names.h"

#define GOST_ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=gostprov", FUNC }, CHECK }
#define GOST_ALG(NAMES, FUNC) GOST_ALGC(NAMES, FUNC, NULL)

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* 
 * List of all algorithms with given OIDs
 */
#define GOSTPROV_OID_CNT 2
const char* gostprov_oid_alg_list[GOSTPROV_OID_CNT] =
{
	"1.2.643.7.1.1.1.1", "gost2012_256",
	//"1.2.643.7.1.1.3.2", "id-tc26-signwithdigest-gost3410-2012-256",
};

/* Parameters we provide to the core */
static const OSSL_PARAM gostprov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    //OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    //OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

//static const OSSL_ALGORITHM gostprov_keyexch[] = {
//    { GOSTPROV_NAMES_GOST2012_256, "provider=gostprov", gostprov_gost2012_256_keyexch_functions },
//    { NULL, NULL, NULL }
//};

static const OSSL_ALGORITHM gostprov_signature[] = {
    { GOSTPROV_NAMES_GOST2012_256, "provider=gostprov", gostprov_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM gostprov_keymgmt[] = {
	{ GOSTPROV_NAMES_GOST2012_256, "provider=gostprov", gostprov_gost2012_256_keymgmt_functions },
    { NULL, NULL, NULL }
};

//static const OSSL_ALGORITHM gostprov_asym_kem[] = {
//    { GOSTPROV_NAMES_GOST2012_256, "provider=gostprov", gostprov_gost2012_256_asym_kem_functions },
//    { NULL, NULL, NULL }
//};

static const OSSL_ALGORITHM gostprov_encoder[] = {
#define ENCODER_PROVIDER "gostprov"
#include "gostprov_encoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM gostprov_decoder[] = {
#define DECODER_PROVIDER "gostprov"
#include "gostprov_decoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};

static const OSSL_PARAM *gostprov_gettable_params(void *provctx)
{
    return gostprov_param_types;
}

/*********************************************************************
 *
 *  Errors
 *
 *****/

/*
 * Ugly hack, to get the errors generated by mkerr.pl.  This should ideally
 * be replaced with a local OSSL_ITEM list of < number, string > pairs as
 * reason strings, but for now, we will simply use GOST_str_reasons.
 * Fortunately, the ERR_STRING_DATA structure is compatible with OSSL_ITEM,
 * so we can return it directly.
 */
static struct proverr_functions_st *err_handle;
#define GOST_PROV
#include "e_gost_err.c"
void ERR_GOST_error(int function, int reason, char *file, int line)
{
    proverr_new_error(err_handle);
    proverr_set_error_debug(err_handle, file, line, NULL);
    proverr_set_error(err_handle, reason, NULL);
}

/*********************************************************************
 *
 *  Provider context
 *
 *****/

static void provider_ctx_free(PROV_CTX *ctx)
{
    if (ctx != NULL) {
        ENGINE_free(ctx->e);
        proverr_free_handle(ctx->proverr_handle);
        OSSL_LIB_CTX_free(ctx->libctx);
    }
    OPENSSL_free(ctx);
}

extern int populate_gost_engine(ENGINE *e);
static PROV_CTX *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                  const OSSL_DISPATCH *in)
{
    PROV_CTX *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL
        && (ctx->libctx = OSSL_LIB_CTX_new()) != NULL
		&& (ctx->corebiometh = gostprov_bio_prov_init_bio_method()) != NULL
        && (ctx->e = ENGINE_new()) != NULL
        && populate_gost_engine(ctx->e)) {
        ctx->core_handle = core;

        /* Ugly hack */
        err_handle = ctx->proverr_handle;
    } else {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*fptr_t)(void);

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *gost_operation(void *vprovctx,
                                                int operation_id,
                                                const int *no_cache)
{
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return GOST_prov_ciphers;
    case OSSL_OP_DIGEST:
        return GOST_prov_digests;
    case OSSL_OP_MAC:
        return GOST_prov_macs;
		
	case OSSL_OP_SIGNATURE: //TODO - not implemented
        return gostprov_signature;
	//case OSSL_OP_KEM: //TODO - not implemented
    //   return gostprov_asym_kem;
    case OSSL_OP_KEYMGMT: //TODO - not implemented
        return gostprov_keymgmt;
    case OSSL_OP_ENCODER: //TODO - not implemented
        return gostprov_encoder;
    case OSSL_OP_DECODER: //TODO - not implemented
        return gostprov_decoder;
    }
    return NULL;
}

static int gost_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL GOST Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* We never fail. */
        return 0;

    return 1;
}

static const OSSL_ITEM *gost_get_reason_strings(void *provctx)
{
#if 0
    return reason_strings;
#endif
    return (OSSL_ITEM *)GOST_str_reasons;
}

/* The function that tears down this provider */
static void gost_teardown(void *vprovctx)
{
    GOST_prov_deinit_ciphers();
    GOST_prov_deinit_digests();
    GOST_prov_deinit_mac_digests();
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (fptr_t)gost_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (fptr_t)gost_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (fptr_t)gost_get_params },
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (fptr_t)gostprov_gettable_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (fptr_t)gost_teardown },
    { 0, NULL }
};

struct prov_ctx_st {
    void *core_handle;
    struct proverr_functions_st *err_handle;
};

#ifdef BUILDING_PROVIDER_AS_LIBRARY
/*
 * This allows the provider to be built in library form.  In this case, the
 * application must add it explicitly like this:
 *
 * OSSL_PROVIDER_add_builtin(NULL, "gost", GOST_provider_init);
 */
# define OSSL_provider_init GOST_provider_init
#endif

OPENSSL_EXPORT
int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
	int i = 0;
	
	OSSL_FUNC_core_obj_create_fn *c_obj_create= NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid= NULL;
	
	if (!gostprov_bio_from_dispatch(in))
        return 0;
	
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
	
	for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
           break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }
    
    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid == NULL)
        return 0;
    
    for (i=0; i<GOSTPROV_OID_CNT;i+=2) {
        if (!c_obj_create(core, gostprov_oid_alg_list[i], gostprov_oid_alg_list[i+1], gostprov_oid_alg_list[i+1])) {
                //ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
                return 0;
        }

        if (!gostprov_set_nid((char*)gostprov_oid_alg_list[i+1], OBJ_sn2nid(gostprov_oid_alg_list[i+1]))) {
              //ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
              return 0;
        }

        if (!c_obj_add_sigid(core, gostprov_oid_alg_list[i+1], "", gostprov_oid_alg_list[i+1])) {
              GOSTPROV_PRINTF2("error registering %s with no hash\n", gostprov_oid_alg_list[i+1]);
              //ERR_raise(ERR_LIB_USER, GOSTPROV_R_NOT_IMPLEMENTED);
              return 0;
        }

        GOSTPROV_PRINTF3("GOSTPROV: successfully registered %s with NID %d\n", gostprov_oid_alg_list[i+1], OBJ_sn2nid(gostprov_oid_alg_list[i+1]));

    }
	
	
    return 1;
}
