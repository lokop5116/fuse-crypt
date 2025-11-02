#include "common.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>

static unsigned char g_key[AES_KEYLEN];
static int g_crypto_ready = 0;

// base64 encryption
// used to store our IV since cJSON can't handle binary arrays for some reason
static char *base64_encode(const unsigned char *input, int length) {

  BIO *bmem = NULL, *b64 = NULL;
  BUF_MEM *bptr;
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  char *buff = malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = 0;
  BIO_free_all(b64);
  return buff;
}

// base64 decryption
static int base64_decode(const char *input, unsigned char *output, int maxlen) {
  BIO *b64, *bmem;
  int len = strlen(input);
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf((void *)input, len);
  bmem = BIO_push(b64, bmem);
  int out_len = BIO_read(bmem, output, maxlen);
  BIO_free_all(bmem);
  return out_len;
}

int encrypt_buffer(const unsigned char *plaintext, int plaintext_len,
                   unsigned char *ciphertext, unsigned char *file_iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;
  int len = 0, ciphertext_len = 0;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, g_key, file_iv)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt_buffer(const unsigned char *ciphertext, int ciphertext_len,
                   unsigned char *plaintext, unsigned char *file_iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;
  int len = 0, plaintext_len = 0;

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, g_key, file_iv)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }

  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int init_encryption() {
  char password[128];
  unsigned char salt[32]; // derived from password

  printf("Enter encryption password: ");
  fgets(password, sizeof(password), stdin);
  password[strcspn(password, "\n")] = 0;

  // derive a deterministic salt from password itself (SHA-256)
  SHA256((unsigned char *)password, strlen(password), salt);

  if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                         PBKDF2_ITER, EVP_sha256(), AES_KEYLEN, g_key)) {
    fprintf(stderr, "PBKDF2 key derivation failed\n");
    return 0;
  }

  memset(password, 0, sizeof(password));
  g_crypto_ready = 1;
  return 1;
}
