/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
// Code inspired by OpenSSL common provider and OQS provider code

#ifndef DECODER_PROVIDER
# error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair         "type-specific"
#define DECODER_STRUCTURE_type_specific_params          "type-specific"
#define DECODER_STRUCTURE_type_specific                 "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub          "type-specific"
#define DECODER_STRUCTURE_EncryptedPrivateKeyInfo       "EncryptedPrivateKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo                "PrivateKeyInfo"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo          "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_DH                            "dh"
#define DECODER_STRUCTURE_DHX                           "dhx"
#define DECODER_STRUCTURE_DSA                           "dsa"
#define DECODER_STRUCTURE_EC                            "ec"
#define DECODER_STRUCTURE_RSA                           "rsa"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                          \
    { _name,                                                            \
      "provider=" DECODER_PROVIDER ",input=" #_input,   \
      (gostprov_##_input##_to_##_output##_decoder_functions) }
#define DECODER_w_structure(_name, _input, _structure, _output)  \
    { _name,                                                            \
      "provider=" DECODER_PROVIDER ",input=" #_input    \
      ",structure=" DECODER_STRUCTURE_##_structure,                     \
      (gostprov_##_structure##_##_input##_to_##_output##_decoder_functions) }

DECODER_w_structure("gost2012_256", der, PrivateKeyInfo, gost2012_256),
DECODER_w_structure("gost2012_256", der, SubjectPublicKeyInfo, gost2012_256),

/*
 * A decoder that takes a SubjectPublicKeyInfo and figures out the types of key
 * that it contains. The output is the same SubjectPublicKeyInfo
 */
//TODO Use if needed
//DECODER_w_structure("DER", der, SubjectPublicKeyInfo, der),
//DECODER("DER", pem, der),
/*
 * A decoder that recognises PKCS#8 EncryptedPrivateKeyInfo structure
 * and decrypts it, passing on the unencrypted PrivateKeyInfo in DER
 * form to the next decoder.
 */
 //TODO Use if needed
//DECODER_w_structure("DER", der, EncryptedPrivateKeyInfo, der),
