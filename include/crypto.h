#ifndef CRYPTO_H
#define CRYPTO_H

#define PASSWD_SIZE 128

#define CHUNK_SIZE 4096

#define ENCRYPTED_CHUNK_SIZE (CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES)

#include <sodium.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/stat.h>
#include "cmdline.h"

#define CHUNK_SIZE 4096

int run_encryption(const char *input_path, const char *output_path, struct gengetopt_args_info *args);

int run_decryption(const char *input_path, const char *output_path, struct gengetopt_args_info *args);

int is_directory(const char *path);

#endif 
