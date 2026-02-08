#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>
#include "cmdline.h"
#include "crypto.h"

// Name for the temporary file during decryption
#define TEMP_TAR_NAME ".temp_crypto_intermediate.tar.gz"

int main(int argc, char **argv) {
  struct gengetopt_args_info args_info;
  int return_code = 1; // Default to error

  if (cmdline_parser(argc, argv, &args_info) != 0) {
      exit(1);
  }

  if (sodium_init() < 0) {
      fprintf(stderr, "Error: libsodium could not be initialized.\n");
      goto cleanup;
  }

  if (args_info.encrypt_given && args_info.decrypt_given) {
      fprintf(stderr, "Error: You cannot use --encrypt and --decrypt simultaneously.\n");
      cmdline_parser_free(&args_info);
      goto cleanup;
  }

  if (!args_info.encrypt_given && !args_info.decrypt_given) {
      fprintf(stderr, "Error: You must specify either --encrypt (-e) or --decrypt (-d).\n");
      goto cleanup;
  }
  
  // Verify existence of input file 
  if (access(args_info.input_arg, F_OK) != 0) {
      fprintf(stderr, "Error: The input file '%s' does not exist.\n", args_info.input_arg);
      cmdline_parser_free(&args_info);
      exit(1);
  }

  // Verify if input and output are equal (Safety check)
  if (args_info.output_arg && strcmp(args_info.input_arg, args_info.output_arg) == 0) {
      fprintf(stderr, "Error: Input and Output files cannot be the same.\n");
      cmdline_parser_free(&args_info);
      exit(1);
  }

  // Verify read permission 
  if (access(args_info.input_arg, R_OK) != 0) {
      fprintf(stderr, "Error: You do not have permission to read '%s'.\n", args_info.input_arg);
      cmdline_parser_free(&args_info);
      exit(1);
  }

  // Sanitize input path (remove trailing slash '/' if present)
  size_t input_len = strlen(args_info.input_arg);
  if (input_len > 1 && args_info.input_arg[input_len - 1] == '/') {
      args_info.input_arg[input_len - 1] = '\0';
  }
  
  char *final_input_path = args_info.input_arg;
  char temp_archive_path[4096];
  int created_temp_file = 0;

  if (args_info.encrypt_given) {
    
    printf("Preparing compression to %s.tar.gz\n", args_info.input_arg);
    snprintf(temp_archive_path, sizeof(temp_archive_path), "%s.tar.gz", args_info.input_arg);
    
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "tar -czf \"%s\" \"%s\"", temp_archive_path, args_info.input_arg);
    
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Critical Error: Failed to execute tar command.\n");
        goto cleanup;
    }
    printf("Compression successful.\n");

    final_input_path = temp_archive_path;
    created_temp_file = 1;

    // If user provided no output name, generate one (e.g., input.tar.gz.enc)
    char *output_path = args_info.output_arg;
    // odd number because of error
    char default_output[4100];
    if (!output_path) {
        snprintf(default_output, sizeof(default_output), "%s.enc", temp_archive_path);
        output_path = default_output;
    }

    return_code = run_encryption(final_input_path, output_path, &args_info);
    
    if (return_code == 2) {
      fprintf(stderr, "Program terminated by user\n");
      goto cleanup;
    } else if(return_code != 0){
      goto cleanup; 
    }

  } else {
    
    // We decrypt to a hidden temporary file first
    char *intermediate_tar = TEMP_TAR_NAME;
    
    printf("Preparing decryption to intermediate file...\n");

    return_code = run_decryption(args_info.input_arg, intermediate_tar, &args_info);
    
    if (return_code == 2) {
      fprintf(stderr, "Program terminated by user\n");
      goto cleanup;
    } else if(return_code != 0){
      fprintf(stderr,"ERROR: decrypt failed\n");
      remove(intermediate_tar); // Clean up if failed
      goto cleanup;
    }

    printf("Preparing extraction...\n");
    char cmd[8192];
    // -k means "keep old files" (do not overwrite)
    snprintf(cmd, sizeof(cmd), "tar -xzkf \"%s\"", intermediate_tar);

    int ret = system(cmd);

    // Always remove the intermediate tar after trying to extract
    remove(intermediate_tar); 

    if(ret != 0){
      fprintf(stderr, "\n WARNING: Extraction stopped to prevent data loss.\n");
      fprintf(stderr, "   The command 'tar' refused to overwrite existing files.\n");
      return_code = 1; 
      goto cleanup;
    } else {
      printf("Extraction successful.\n");
    }
  }
  
  // Set success code
  return_code = 0;

  // Only runs if return_code is 0 (Success)
  if (return_code == 0 && args_info.remove_input_given) {
    printf("Removing original input: '%s'...\n", args_info.input_arg);

    // Check if it is a directory
    if (is_directory(args_info.input_arg)) {
      char cmd[8192];
      snprintf(cmd, sizeof(cmd), "rm -rf \"%s\"", args_info.input_arg);
      
      if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Could not remove directory '%s'. Check permissions.\n", args_info.input_arg);
      } else {
        printf("   Directory removed successfully.\n");
      }
    } 
    else {
      if (remove(args_info.input_arg) != 0) {
        perror("Warning: Could not remove input file");
      } else {
        printf("   File removed successfully.\n");
      }
    }
  }

  cleanup:
    cmdline_parser_free(&args_info);

    // Clean up temporary .tar.gz created during encryption
    if(created_temp_file){
      if (remove(final_input_path) != 0) {
          // Silent or low priority warning
      } else {
          printf("Temp file cleanup successful\n");
      }
    }
   
  return return_code;
}
