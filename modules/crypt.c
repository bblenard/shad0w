#include <windows.h>
#include <stdio.h>
#include "base64.h"

/**
 * decrypt_string - base64 decodes and xor decrypts string with given key
 * @encrypted_string: base64 and xor encoded string to be "decrypted"
 * @key: xor key
 * Returns: Allocated decrypted buffer,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 * TODO: Remove base64 decoding from this function. Based on the function name
 *       the caller has no reason to know that the encrypted string being passed
 *       is also base64 encoded.
 */
char* decrypt_string(char* encrypted_string, int key)
{
    size_t i;

    size_t out_len   = 0;
    size_t encrypted_string_length = strlen(encrypted_string);

    unsigned char *out_buffer = base64_decode((const unsigned char *)encrypted_string, encrypted_string_length, &out_len);
    unsigned char *decrypted_buffer = malloc(out_len + 1);
    if (decrypted_buffer == NULL) {
        return NULL;
    }

    for (i = 0; i < out_len; i++)
    {
        decrypted_buffer[i] = out_buffer[i] ^ key;
    }
    decrypted_buffer[i] = '\0';
    free(out_buffer);

    return decrypted_buffer;
}