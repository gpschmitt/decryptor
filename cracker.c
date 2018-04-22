#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LENGTH 16
#define IV_LENGTH 16

// ==== FUNCTION HEADERS ====
int filesize(FILE * file);
unsigned char * readFileContents(FILE * file);
char * findKey(FILE * dictionary,
               const unsigned char * plaintext,
               const unsigned char * ciphertext);
int testKey(const unsigned char * key,
            const unsigned char * plaintext,
            const unsigned char * expectedCiphertext);
int strequals(const char * str1, const char * str2);
// ==========================


/*
 * Expected argv format: ["./enc", "plaintextFilename", "ciphertextFilename", "dictionaryFilename"]
 */
int main(int argc, const char * argv[]) {
    FILE * plaintextFile, * ciphertextFile, * dictionaryFile;
    char * plaintext, * ciphertext, * key;
    
    puts("Checking argument format...");
    if (argc <= 3) {
        puts("ERROR: Incorrect argument format! Exiting...");
        exit(1);
    }

    puts("Reading contents of plaintext and ciphertext...");
    // Open files
    plaintextFile = fopen(argv[1], "rb");
    ciphertextFile = fopen(argv[2], "rb");
    dictionaryFile = fopen(argv[3], "r");

    // Read file contents
    plaintext = readFileContents(plaintextFile);
    ciphertext = readFileContents(ciphertextFile);

    // Close files
    fclose(plaintextFile);
    fclose(ciphertextFile);

    puts("Finding key...");
    key = findKey(dictionaryFile, plaintext, ciphertext);

    puts("Program complete.");
    printf("Key: %s\n", key);

    free(key);
    free(plaintext);
    free(ciphertext);
    fclose(dictionaryFile);
    return 0;
}

/*
 * Gets the size of the file.
 */
int filesize(FILE * file) {
    int current, size;

    // Save current file position
    current = ftell(file);

    // Go to end of file and get position
    fseek(file, 0, SEEK_END);
    size = ftell(file);

    // Reset to previous file position and return file size
    fseek(file, 0, current);
    return size;
}

/*
 * Returns a dynamically allocated, null-terminated string containing the contents of file.
 * The user should free the result when done.
 */
unsigned char * readFileContents(FILE * file) {
    unsigned char * contents;
    int size;

    size = filesize(file);
    contents = malloc(sizeof(char) * (size + 1));
    fread(contents, sizeof(char), size, file);
    contents[size] = '\0';
    return contents;
}

/*
 * Searches through dictionary (a file containing newline separated words), finding which
 * word in the dictionary was used as a key to encrypt plaintext into ciphertext.
 * Note that if the key is less than KEY_LENGTH characters, it will be padded with spaces.
 */
char * findKey(FILE * dictionary,
               const unsigned char * plaintext,
               const unsigned char * ciphertext) {
    int i, returnVal;
    char * key = (char *) malloc(sizeof(char) * KEY_LENGTH);
    char * word = NULL;
    size_t wordsize = 0;
    ssize_t charsRead = 0;

    word = NULL;
    wordsize = sizeof(char) * KEY_LENGTH;

    puts("Reading dictionary...");
    while (charsRead != -1) {
        // Read a word from dictionary
        charsRead = getline(&word, &wordsize, dictionary);
        
        // Copy word into key, pad with spaces to KEY_LENGTH, and null terminate it
        strcpy(key, word);
        for (i = charsRead - 1; i < KEY_LENGTH; i++) {
            key[i] = ' ';
        }
        key[KEY_LENGTH] = '\0';

        // Test key
        returnVal = testKey(key, plaintext, ciphertext);

        if (returnVal > 0) {
            // Key successful
            puts("Key found!");
            return key;
        } else if (returnVal < 0) {
            // Error
            puts("ERROR: EVP error took place when testing key.");
            free(key);
            exit(1);
        }
    }
    puts("ERROR: key not found.");
    free(key);
    exit(1);
}

/*
 * Tests whether encrypting plaintext with key produces expectedCiphertext.
 * Returns 1 if it does, 0 if it doesn't, and -1 if an error occurs.
 */
int testKey(const unsigned char * key,
            const unsigned char * plaintext,
            const unsigned char * expectedCiphertext) {
    int i;
    int plainLength = strlen(plaintext);
    int cipherLength = strlen(expectedCiphertext);
    int returnVal = 0;
    unsigned char * ciphertext = malloc(sizeof(char) * (cipherLength + 1));
    const unsigned char iv[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // Create and initialize cipher context
    EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(context, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    
    // Check that our key and iv are of proper length
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == KEY_LENGTH);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(context) == IV_LENGTH);

    // Assign key and iv
    EVP_CipherInit_ex(context, NULL, NULL, key, iv, 1);

    // Cipher first block
    if (EVP_CipherUpdate(context, ciphertext, &cipherLength, plaintext, plainLength)) {
        // Cipher last block
        if (EVP_CipherFinal_ex(context, &(ciphertext[cipherLength]), &cipherLength)) {
            // ciphertext successfully generated, compare to expected
            returnVal = strequals(ciphertext, expectedCiphertext);
        } else {
            // Error encountered
            returnVal = -1;
        }
    } else {
        // Error encountered
        returnVal = -1;
    }

    // Perform cleanup
    free(ciphertext);
    //EVP_CIPHER_CTX_free(context);

    return returnVal;
}

/*
 * If str1 and str2 are bitwise equal, returns 1. Else returns 0.
 */
int strequals(const char * str1, const char * str2) {
    return !strcmp(str1, str2);
}
