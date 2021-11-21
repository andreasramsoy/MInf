#ifndef __POPCORN_CRYPTO__
#define __POPCORN_CRYPTO__

#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

/**
 * Header file for encryption used by the popcorn subsystem
 */

#define POPCORN_ENCRYPTION_ON

// encryption
#define POPCORN_AES_KEY_SIZE 256 //currently considered safe (written in 2021), but will increase in future
#define POPCORN_AES_KEY_SIZE_BYTES POPCORN_AES_KEY_SIZE / 8
#define POPCORN_AES_IV_LENGTH 16




#endif