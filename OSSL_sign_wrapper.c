#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// Wrapper function for performing ECDSA signing using OpenSSL's EVP
/*
* Parameters:
*   Return: 0 = Success; 1 = Failure
*   Inputs: EVP_PKEY *evp_key - Pointer to the private key
*           uint8_t *data - Pointer to the data to be signed
*           uint32_t data_size - Size of the data to be signed
*   Output: unsigned char **signature - Pointer to the signature
*/
int openssl_ecdsa_sign(const uint8_t *data, uint32_t data_size, const EVP_PKEY *evp_key, unsigned char **signature, size_t *signature_size) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) {
        printf("issue1\n");
        return 1;
    }

    if (1 != EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, evp_key)) {
        printf("issue2\n");
        return 1;
    }

    if (1 != EVP_DigestSignUpdate(mctx, data, data_size)) {
        printf("issue3\n");
        return 1;
    }

    if (1 != EVP_DigestSignFinal(mctx, NULL, signature_size)) {
        printf("issue4\n");
        return 1;
    }

    size_t sig_size = *(signature_size);

    *signature = (unsigned char*)OPENSSL_malloc(sig_size);
    if (*signature == NULL) {
        printf("issue5\n");
        return 1;
    }

    if (1 != EVP_DigestSignFinal(mctx, *signature, signature_size)) {
        printf("issue7\n");
        return 1;
    }

    EVP_MD_CTX_free(mctx);

    return 0;
}

// Function to verify an ECDSA signature
// 1 for success, 0 for failure
int verify_ecdsa_signature(const uint8_t *data, uint32_t data_size, const EVP_PKEY *evp_key, const unsigned char *signature, size_t signature_size) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) {
        return 0;
    }

    if (1 != EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, evp_key)) {
        return 0;
    }

    if (1 != EVP_DigestVerifyUpdate(mctx, data, data_size)) {
        return 0;
    }

    int result = EVP_DigestVerifyFinal(mctx, signature, signature_size);
    EVP_MD_CTX_free(mctx);

    return result; // 1 for success, 0 for failure
}

int main() {
    const uint8_t data[] = "Hello, World!";
    uint32_t data_size = sizeof(data);

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Create an EC_KEY with NIST P-256 curve
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "Error: Unable to create EC_KEY\n");
        return 1;
    }

    if (1 != EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Error: Unable to generate the private key\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(evp_key, ec_key)) {
        fprintf(stderr, "Error: Unable to set EC_KEY in EVP_PKEY\n");
        EVP_PKEY_free(evp_key);
        EC_KEY_free(ec_key);
        return 1;
    }

    size_t signature_size = 0;
    unsigned char *signature = NULL;

    if (openssl_ecdsa_sign(data, data_size, evp_key, &signature, &signature_size) == 0) {
        printf("ECDSA Signature:\n");
        for (size_t i = 0; i < signature_size; i++) {
            printf("%02X", signature[i]);
        }
        printf("\n");

        // Verify the signature
        if (verify_ecdsa_signature(data, data_size, evp_key, signature, signature_size)) {
            printf("Signature verified successfully!\n");
        } else {
            printf("Signature verification failed.\n");
        }
    } 
    else {
        fprintf(stderr, "Error: Unable to sign the data1\n");
    }

    if (signature) {
        free(signature);
    }

    EVP_PKEY_free(evp_key);
    EC_KEY_free(ec_key);
    ERR_free_strings();

    return 0;
}
