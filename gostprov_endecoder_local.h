// Code inspired by OpenSSL common provider and OQS provider code

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include "gost_prov.h"

OSSL_FUNC_keymgmt_new_fn *gostprov_get_keymgmt_new(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_free_fn *gostprov_get_keymgmt_free(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_import_fn *gostprov_get_keymgmt_import(const OSSL_DISPATCH *fns);
OSSL_FUNC_keymgmt_export_fn *gostprov_get_keymgmt_export(const OSSL_DISPATCH *fns);

int gostprov_der_from_p8(unsigned char **new_der, long *new_der_len,
                          unsigned char *input_der, long input_der_len,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg);

void *gostprov_import_key(const OSSL_DISPATCH *fns, void *provctx,
                           int selection, const OSSL_PARAM params[]);
void gostprov_free_key(const OSSL_DISPATCH *fns, void *key);
int gostprov_read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  unsigned char **data,
                  long *len);
