/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// Code inspired by OpenSSL common provider and OQS provider code

#ifndef ENCODER_PROVIDER
# error Macro ENCODER_PROVIDER undefined
#endif

#define ENCODER_STRUCTURE_type_specific_keypair         "type-specific"
#define ENCODER_STRUCTURE_type_specific_params          "type-specific"
#define ENCODER_STRUCTURE_type_specific                 "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub          "type-specific"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo       "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo                "PrivateKeyInfo"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo          "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_DH                            "dh"
#define ENCODER_STRUCTURE_DHX                           "dhx"
#define ENCODER_STRUCTURE_DSA                           "dsa"
#define ENCODER_STRUCTURE_EC                            "ec"
#define ENCODER_STRUCTURE_RSA                           "rsa"
#define ENCODER_STRUCTURE_PKCS1                         "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                         "pkcs3"
#define ENCODER_STRUCTURE_X9_42                         "X9.42"
#define ENCODER_STRUCTURE_X9_62                         "X9.62"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                                \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=text",      \
      (gostprov_##_sym##_to_text_encoder_functions) }
#define ENCODER(_name, _sym, _output)                            \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=" #_output, \
      (gostprov_##_sym##_to_##_output##_encoder_functions) }
#define ENCODER_w_structure(_name, _sym, _output, _structure)    \
    { _name,                                                            \
      "provider=" ENCODER_PROVIDER ",output=" #_output  \
      ",structure=" ENCODER_STRUCTURE_##_structure,                     \
      (gostprov_##_sym##_to_##_structure##_##_output##_encoder_functions) }

/*
 * Entries for human text "encoders"
 */
// TODO Use if needed
//ENCODER_TEXT("GOST2012_256", gost2012_256),


/*
 * Entries for key type specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "type-specific",
 *                                   NULL, NULL);
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", "type-specific",
 *                                   NULL, NULL);
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */
 
//TODO Use if needed
// /* The RSA encoders only support private key and public key output */
// ENCODER_w_structure("RSA", rsa, yes, der, type_specific_keypair),
// ENCODER_w_structure("RSA", rsa, yes, pem, type_specific_keypair),
// #ifndef OPENSSL_NO_DH
// /* DH and X9.42 DH only support key parameters output. */
// ENCODER_w_structure("DH", dh, yes, der, type_specific_params),
// ENCODER_w_structure("DH", dh, yes, pem, type_specific_params),
// ENCODER_w_structure("DHX", dhx, yes, der, type_specific_params),
// ENCODER_w_structure("DHX", dhx, yes, pem, type_specific_params),
// #endif
// #ifndef OPENSSL_NO_DSA
// ENCODER_w_structure("DSA", dsa, yes, der, type_specific),
// ENCODER_w_structure("DSA", dsa, yes, pem, type_specific),
// #endif
// #ifndef OPENSSL_NO_EC
// /* EC only supports keypair and parameters DER and PEM output. */
// ENCODER_w_structure("EC", ec, yes, der, type_specific_no_pub),
// ENCODER_w_structure("EC", ec, yes, pem, type_specific_no_pub),
// /* EC supports blob output for the public key */
// ENCODER("EC", ec, yes, blob),
// # ifndef OPENSSL_NO_SM2
// ENCODER_w_structure("SM2", sm2, no, der, type_specific_no_pub),
// ENCODER_w_structure("SM2", sm2, no, pem, type_specific_no_pub),
// ENCODER("SM2", sm2, no, blob),
// # endif
// #endif


/*
 * Entries for encrypted PKCS#8 (EncryptedPrivateKeyInfo), unencrypted PKCS#8
 * (PrivateKeyInfo) and SubjectPublicKeyInfo.  The "der" ones are added
 * convenience for any user that wants to use OSSL_ENCODER directly.
 * The "pem" ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 */
ENCODER_w_structure("gost2012_256", gost2012_256, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("gost2012_256", gost2012_256, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("gost2012_256", gost2012_256, der, PrivateKeyInfo),
ENCODER_w_structure("gost2012_256", gost2012_256, pem, PrivateKeyInfo),
ENCODER_w_structure("gost2012_256", gost2012_256, der, SubjectPublicKeyInfo),
ENCODER_w_structure("gost2012_256", gost2012_256, pem, SubjectPublicKeyInfo),