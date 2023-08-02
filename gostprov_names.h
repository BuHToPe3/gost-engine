/*
 * Copyright 2021-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Macros for use as names and descriptions in our providers' OSSL_ALGORITHM.
 *
 * All the strings are formatted the same way:
 *
 *     Our primary name[:other names][:numeric OID]
 *
 * 'other names' include historical OpenSSL names, NIST names, ASN.1 OBJECT
 * IDENTIFIER names, and commonly known aliases.
 *
 * Where it matters, our primary names follow this format:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 */


#define GOSTPROV_NAMES_GOST2012_256 "gost2012_256"
#define GOSTPROV_DESCS_GOST2012_256 "GOST R 34.10-2012 with 256 bit key implementation"
