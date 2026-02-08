#include "crypto.h"

// function return 1 then the file is a directory
// return 0 if anything else
int is_directory(const char *path) {
  struct stat path_stat;
  if (stat(path, &path_stat) != 0) {
      return 0;
  }
  return S_ISDIR(path_stat.st_mode);
}

// handles encryption process
int run_encryption(const char *input_path, const char *output_path, struct gengetopt_args_info *args){
  (void)args;
  /* 1. Open files and validate */
  // verify the existence of the file given
  int return_code = 1;
  char *user_password = NULL;
  char *password_aux = NULL;
  char *generated_output = NULL;
  struct termios oldt, newt;
  unsigned char *key = NULL; 
  FILE *fin  = NULL;
  FILE *fout = NULL;
  crypto_secretstream_xchacha20poly1305_state state;

  if(access(input_path, F_OK) != 0){
    perror("Specified file in input_path does not exist");
    goto cleanup;
  }
  // verify if output path not given 
  if(output_path == NULL){
    // when no output name specified use filename.extension.enc
    size_t len = strlen(input_path);
    generated_output = malloc(len + 5);
    if(generated_output == NULL){
      perror("Failed to allocate memory for output filename");
      goto cleanup;
    }
    // copy input_path to generated_output
    strcpy(generated_output, input_path);
    strcat(generated_output, ".enc");
    output_path = generated_output;
  }
  // verify if there already exists a file: filename.extension.enc 
  if(access(output_path, F_OK) == 0){
    int confirmation_char, clearbuffer_aux;
    do{
      do{
        printf("File '%s' already exists. Overwrite? [y/n]: ", output_path);
        confirmation_char = getchar();
        if(confirmation_char == EOF){
          break;
        }
      }while(confirmation_char == ' ' ||
             confirmation_char == '\t');
      
      if(confirmation_char == EOF){
        break;
      }
      if(confirmation_char == '\n'){
        // if only enter is pressed default behavior
        // is set to denial of action
        confirmation_char = 'n';
      }else{
        // cleans the residuals left in the buffer
        while ((clearbuffer_aux = getchar()) != '\n' && clearbuffer_aux != EOF);
      }
      // tolower for better compatability 
      confirmation_char = tolower((unsigned char)confirmation_char);
    
    }while(confirmation_char != 'y' &&
          confirmation_char != 'n');
    
    if(confirmation_char == 'n'){
      return_code = 2;
      goto cleanup;
    }
  }
  // confirmation_char = 'y'
  // get current terminal attributes
  

  /* 2. Securely read password into a buffer */
  if (tcgetattr(STDIN_FILENO, &oldt) != 0){
    perror("ERROR aplying changes to terminal with tcgetattr");
    goto cleanup;
  }
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  user_password = sodium_malloc(PASSWD_SIZE);
  if(user_password == NULL){
    perror("Memory allocation failed for user_password");
    goto cleanup;
  }
  password_aux = sodium_malloc(PASSWD_SIZE);
  if(password_aux == NULL){
    perror("Memory allocation failed for password_aux");
    goto cleanup;
  }
  printf("Do not panic if writing is invisible\n");
  int match_passwords = 0;
  do { // do while cycle to get password 
    printf("Enter secret encryption password: ");
    if(fgets(user_password, PASSWD_SIZE, stdin) == NULL){
      perror("ERROR while attempting to grab user_password");
      goto cleanup;
    }
    // remove \n and add \0
    user_password[strcspn(user_password, "\n")] = '\0';
    printf("\n");
    printf("Confirm encryption password:");
    if(fgets(password_aux, PASSWD_SIZE, stdin) == NULL){
      perror("ERROR while attempting to grab password_aux");
      goto cleanup;
    }
    printf("\n");
    // remove \n and add \0 
    password_aux[strcspn(password_aux, "\n")] = '\0';
    if(strcmp(password_aux, user_password) == 0){
      match_passwords = 1;
    }
    else{
      printf("Passwords do not match! Be more carefull\n");
    }

  } while (match_passwords != 1);
  // passwords match
  
  /* 3. Generate Salt and derive Key */
  // crypto_pwhash(key, sizeof key, password, ..., salt, opslimit, memlimit, ...)
  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof salt);
  key = sodium_malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
  if(key == NULL){
    perror("Memory allocation failed for key");
    goto cleanup;
  }
  if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES, 
      user_password, 
      strlen(user_password), 
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE, 
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Out of memory during key derivation\n");
    goto cleanup;
  }

  fin  = fopen(input_path, "rb");
  if(fin == NULL){
    perror("ERROR opening input file");
    goto cleanup;
  }
  fout = fopen(output_path, "wb");
  if(fout == NULL){
    perror("ERROR opening or creating output file");
    goto cleanup;
  }

  /* 4. Write Header to output file (Salt + Stream Header) */
  // writes the salt, necessary for Argon2id while desencrypting

  // writes the stream header to inicialize XChaCha20
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
  fwrite(salt, 1, crypto_pwhash_SALTBYTES, fout);
  fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, fout);

  /* 5. Processing loop (Read chunk -> Push -> Write chunk) */
  unsigned char in_buffer[CHUNK_SIZE];
  unsigned char out_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned long long out_len;
  size_t n;
  unsigned char tag;
  do{
    n = fread(in_buffer, 1, CHUNK_SIZE, fin);
    if(feof(fin)){
      tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    }else{
      tag = 0;
    }

    if (crypto_secretstream_xchacha20poly1305_push(&state, out_buffer, &out_len, 
                                                  in_buffer, n, NULL, 0, tag) != 0) {
        fprintf(stderr, "Error during encryption push\n");
        return_code = 1;
        goto cleanup;
    }

    if (fwrite(out_buffer, 1, out_len, fout) != out_len) {
        perror("Error writing encrypted data");
        return_code = 1;
        goto cleanup;
    }
  }while(tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL);
  
  printf("Input file: '%s' encrypted to '%s'\n", input_path, output_path);

  return_code = 0;

  cleanup:
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    if(fin){
      fclose(fin);
    }
    if(fout){
      fclose(fout);
    }

    if (user_password != NULL) {
        sodium_memzero(user_password, PASSWD_SIZE);
        sodium_free(user_password);
    }
    if (password_aux != NULL) {
        sodium_memzero(password_aux, PASSWD_SIZE);
        sodium_free(password_aux);
    }

    if(key != NULL){
      sodium_memzero(key, 32);
      sodium_free(key);
    }
    
    free(generated_output);

    sodium_memzero(&state, sizeof state);

    return return_code;
}

// handles the decryption process.
int run_decryption(const char *input_path, const char *output_path, struct gengetopt_args_info *args){
  (void)args;
  FILE *fin = NULL;
  FILE *fout = NULL;
  int return_code = 1;
  struct termios oldt, newt;
  char *generated_output = NULL;
  char *user_password = NULL;
  unsigned char *key = NULL;
  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state state;

  if(access(input_path, F_OK) != 0){
    perror("Specified file in input_path does not exist");
    goto cleanup;
  }
  // verify if output path not given 
  if(output_path == NULL){
    // when no output name specified use filename.extension.enc
    size_t len = strlen(input_path);
    generated_output = malloc(len + 5);
    if(generated_output == NULL){
      perror("Failed to allocate memory for output filename");
      goto cleanup;
    }
    // copy input_path to generated_output
    strcpy(generated_output, input_path);
    strcat(generated_output, ".decn");
    output_path = generated_output;
  }
  // verify if there already exists a file: filename.extension.enc 
  if(access(output_path, F_OK) == 0){
    int confirmation_char, clearbuffer_aux;
    do{
      do{
        printf("File '%s' already exists. Overwrite? [y/n]: ", output_path);
        confirmation_char = getchar();
        if(confirmation_char == EOF){
          break;
        }
      }while(confirmation_char == ' ' ||
             confirmation_char == '\t');
      
      if(confirmation_char == EOF){
        break;
      }
      if(confirmation_char == '\n'){
        // if only enter is pressed default behavior
        // is set to denial of action
        confirmation_char = 'n';
      }else{
        // cleans the residuals left in the buffer
        while ((clearbuffer_aux = getchar()) != '\n' && clearbuffer_aux != EOF);
      }
      // tolower for better compatability 
      confirmation_char = tolower((unsigned char)confirmation_char);
    
    }while(confirmation_char != 'y' &&
          confirmation_char != 'n');
    
    if(confirmation_char == 'n'){
      return_code = 2;
      goto cleanup;
    }
  }

  // fin corresponds to the encrypted file
  fin = fopen(input_path, "rb");
  fout = fopen(output_path, "wb");
  if(fin == NULL){
    perror("ERROR opening encrypted file");
    goto cleanup;
  }
  if(fout == NULL){
    perror("ERROR opening or creating output file");
    goto cleanup;
  }
  // read salt 
  size_t read_len = 0;
  read_len = fread(salt, 1, crypto_pwhash_SALTBYTES, fin);
  if(read_len != crypto_pwhash_SALTBYTES){
    perror("ERROR reading salt header");
    printf("If it is a directory please add -c\n");
    goto cleanup;
  }
  // read header
  read_len = fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, fin);
  if(read_len != crypto_secretstream_xchacha20poly1305_HEADERBYTES){
    perror("ERROR reading header");
    goto cleanup;
  }

  if (tcgetattr(STDIN_FILENO, &oldt) != 0){
    perror("ERROR aplying changes to terminal with tcgetattr");
    goto cleanup;
  }
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  user_password = sodium_malloc(PASSWD_SIZE);
  if(user_password == NULL){
    perror("Memory allocation failed for user_password");
    goto cleanup;
  }
  
  printf("Do not panic if writing is invisible\n");
  printf("Enter secret encryption password: ");
  if(fgets(user_password, PASSWD_SIZE, stdin) == NULL){
    perror("ERROR while attempting to grab user_password");
    goto cleanup;
  }
  printf("\n");
  // remove \n and add \0
  user_password[strcspn(user_password, "\n")] = '\0';

  key = sodium_malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
  if(key == NULL){
    perror("Out of memory for key");
    goto cleanup;
  }

  if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES, 
        user_password, 
        strlen(user_password), 
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE, 
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Out of memory during key derivation\n");
    goto cleanup;
  } 

  if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
    fprintf(stderr, "Error: Invalid header. Wrong password or corrupted file.\n");
    goto cleanup;
  }

  unsigned char in_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char out_buffer[CHUNK_SIZE];
  unsigned long long out_len;
  read_len = 0;
  unsigned char tag = 0;
  do{
    read_len = fread(in_buffer, 1, sizeof(in_buffer), fin);
    if(read_len == 0){
      break;
    }

    if (crypto_secretstream_xchacha20poly1305_pull(&state, 
                                                   out_buffer, 
                                                   &out_len, 
                                                   &tag, 
                                                   in_buffer, 
                                                   read_len, 
                                                   NULL, 
                                                   0) != 0) {
      fprintf(stderr, "Error during decryption (corrupted chunck or wrong key)\n");
      goto cleanup;
    }

    if (fwrite(out_buffer, 1, out_len, fout) != out_len) {
      perror("Error writing encrypted data");
      goto cleanup;
    }
  }while(tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL);

  if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
    fprintf(stderr, "Error: Premature end of file (File is truncated).\n");
    goto cleanup;
  }

  printf("Input file: '%s' decrypted to '%s'\n", input_path, output_path);

  return_code = 0;

  cleanup:
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    if(fin){
      fclose(fin);  
    }
    if(fout){
      fclose(fout);
    }
  
    free(generated_output);

    if (user_password != NULL) {
      sodium_memzero(user_password, PASSWD_SIZE);
      sodium_free(user_password);
    }
    if (key != NULL){
      sodium_memzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
      sodium_free(key);    
    }

    return return_code;
}
