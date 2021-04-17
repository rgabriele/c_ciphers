// USE C90 STANDARD PLEASE
/*
 * Riley Gabriele
 * 250921157
 * CS2211 ASN 4
 */
/*
 * This program implements ciphers.h. It allows caesar cipher encryption and decryption, vigenere encryption and decryption,
 * and a frequency analysis of letters in encrypted ciphertext.
 */

#include "ciphers.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <ctype.h>
char alpha[] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

char * caesar_encrypt(char *plaintext, int key) {

    // Initialize variables and allocate space in the heap for the encrypted text
    char *p, *q, *encrypt = (char *) malloc((strlen(plaintext) + 1) * sizeof(char));
    int index;

    // Print error message if memory can't be allocated
    if (encrypt == NULL) {
        printf("Error allocating memory!");
        exit(EXIT_FAILURE);
    }

    for(p = plaintext, q = encrypt; *p != '\0'; p++, q++) {     // Iterate through memory of plaintext and encrypt

        if (!isalpha(*p)) {                                     // If the character is not a letter (punct, spaces, numbers etc.)

            *q = *p;                                            // Copy character from plaintext to the encrypt

        } else {
            // Convert to uppercase
            *p = toupper((unsigned char) *p);

            for (int i = 0; alpha[i] != 0; i++) {
                if (*p == alpha[i]) {
                    index = (i + key) % 26;                 // Manage wrapping around alphabet using modulus
                    if (index < 0) {
                        index = 26 + index;                 // Account for negative numbers
                        *q = alpha[index];
                    } else {
                        *q = alpha[index];
                    }
                }
            }
        }
    }
    *(encrypt + strlen(plaintext)) = '\0';  // Add null as end of string
    return encrypt;     // This memory is freed in the main function
}

char * caesar_decrypt(char *ciphertext, int key) {
    // Initialize variables and allocate space in the heap for the encrypted text
    char *p, *q, *decrypt = (char *) malloc((strlen(ciphertext) + 1) * sizeof(char));
    int index;
    // Print error message if memory can't be allocated
    if (decrypt == NULL) {
        printf("Error allocating memory!");
        exit(EXIT_FAILURE);
    }

    for(p = ciphertext, q = decrypt; *p != '\0'; p++, q++) {        // Same as encrypt method but instead subtract the key to decrypt

        if (!isalpha(*p)) {

            *q = *p;

        } else {

            *p = toupper((unsigned char) *p);

            for (int i = 0; alpha[i] != 0; i++) {
                if (*p == alpha[i]) {
                    index = (i - key) % 26;
                    if (index < 0) {
                        index = 26 + index;
                        *q = alpha[index];
                    } else {
                        *q = alpha[index];
                    }
                }
            }
        }
    }
    *(decrypt + strlen(ciphertext)) = '\0';     // add null terminator to end of string
    return decrypt;         // This memory is freed in main
}

char * vigen_encrypt(char *plaintext, char *key) {
    // Initialize variables and allocate space
    char *p, *q, *betterkey = (char *) malloc((strlen(plaintext) + 1) * sizeof(char));
    int plainpos,paddedpos;
    // Print error message if memory can't be allocated
    if (betterkey == NULL) {
        printf("Error allocating memory!");
        exit(EXIT_FAILURE);
    }
    // Pad the key
    for (p = key, q = betterkey; strlen(betterkey) < strlen(plaintext); p++, q++) {     // while the padded key is not the same length as the
        if(*p == '\0') {
            // If you reach the end of the key then reset the index to the beginning so you can repeat
            p = p - strlen(key);
        }
        *q = *p;
    }


    for(p = plaintext, q = betterkey; *p != '\0'; p++, q++) {

        if(!isalpha(*p)) {  // If its punctuation or whitespace then copy right away
            *q = *p;
        } else {
            *p = toupper((unsigned char)*p);

            for(int x = 0; alpha[x] != 0; x++) {        // Find position of the plaintext letter in the alphabet
                if(*p == alpha[x]) {
                    plainpos = x;
                    break;
                }
            }
            for(int y = 0; alpha[y] != 0; y++) {        // Find position fo the padded key letter  in the alphabet
                if(*q == alpha[y]) {
                    paddedpos = y;
                    break;
                }
            }
            *p = alpha[(plainpos + paddedpos) % 26];        // Manage wrapping
        }
    }
    free(betterkey);    // Free the memory
    return plaintext;
}

char * vigen_decrypt(char *ciphertext, char *key) {
    // Same as above function except this function subtracts the position of the padded letter from the position of the ciphertext letter
    char *p, *q, *betterkey = (char *) malloc((strlen(ciphertext) + 1) * sizeof(char));
    int plainpos, paddedpos, result;

    if (betterkey == NULL) {
        printf("Error allocating memory!");
        exit(EXIT_FAILURE);
    }

    for (p = key, q = betterkey; strlen(betterkey) < strlen(ciphertext); p++, q++) {
        if(*p == '\0') {
            p = p - strlen(key);
        }
        *q = *p;
    }

    for(p = ciphertext, q = betterkey; *p != '\0'; p++, q++) {
        if(!isalpha(*p)) {
            *q = *p;
        } else {
            *p = toupper((unsigned char) *p);

            for (int x = 0; alpha[x] != 0; x++) {
                if (*p == alpha[x]) {
                    plainpos = x;
                    break;
                }
            }
            for (int y = 0; alpha[y] != 0; y++) {
                if (*q == alpha[y]) {
                    paddedpos = y;
                    break;
                }
            }
            result = (plainpos - paddedpos) % 26;
            if (result < 0) {
                result = 26 + result;
                *p = alpha[result];
            }

            *p = alpha[result % 26];
        }
    }
    free(betterkey);
    return ciphertext;
}

void freq_analysis(char *ciphertext, double letters[26]) {
    // Declare variables
    int ascii, valid = 0;
    double *ptr;
    char *ciph;
    ptr = letters;

    // Set all values in array to zero
    for(int i = 0; i < 26; i++) {
        *(ptr + i) = 0;
    }

    // Iterate through cipher text
    for(ciph = ciphertext; *ciph != '\0'; ciph++) {
        toupper(*ciph);                                 // Convert to uppercase
        ascii = (int) *ciph;                            // Get ascii code
        if(ascii >= 65 && ascii <= 98) {                // If this a capital letter
            valid++;
            *(ptr + (ascii - 65)) += 1;
        } else {
            continue;                                   // If not a valid letter then continue
        }
    }
}
