// USE C90 STANDARD PLEASE
// Riley Gabriele
// 250921157
// CS2211 ASN 4
#include "ciphers.h"
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <ctype.h>

int main() {
    // Declare variables
    double freqarray[26];
    char input[50], *enret, *deret, *newlineposition;
    int cipher;

    // Get plaintext input
    printf("Input plaintext:\n");
    fgets(input,50,stdin);

    // Remove newline from the input
    if ((newlineposition = strchr(input, '\n')) != NULL) {
        *newlineposition = '\0';
    }

    // Print available ciphers
    printf("\nAvailable Ciphers:\n1) Caesar\n2) Vigenere\n\nSelect Cipher: ");
    scanf("%d",&cipher);        // Scan cipher in
    while(getchar() != '\n');   // Clear input buffer

    // Error check cipher selection
    if (cipher > 2 || cipher < 0) {
        printf("Error: bad selection!");
        exit(EXIT_FAILURE);
    }

    if (cipher == 1) {      // If caesar cipher

        int key;
        // Scan in number key
        printf("\nInput key as number: ");
        scanf("%d",&key);

        while(getchar() != '\n');       // Clear input buffer

        // Print plaintext input
        printf("\nPlaintext:\n%s\n", input);

        // Print encrypted text
        enret = caesar_encrypt(input,key);
        printf("\nCiphertext:\n%s\n",enret);


        // Print decrypted ciphertext
        deret = caesar_decrypt(enret,key);
        printf("\nDecrypted plaintext:\n%s\n",deret);
        freq_analysis(enret, freqarray);
        free(enret);                            // Free memory now that we're done
        free(deret);

        // Print frequency analysis
        printf("\nFrequency Analysis:\n");
        char c;
        for (c = 'A'; c <= 'Z'; ++c) {      // Print formatted alphabet
            printf("%10c", c);
        }
        printf("\n");
        for (int i = 0; i < 26; i++) {      // Print formatted array of occurrence values
            printf("%10.1f", (freqarray[i]/strlen(input)) * 100);
        }


    } else if (cipher == 2) {       // If vigenere cipher

        char key[50], *p, c;
        // Take input for string key
        printf("Input key as string: ");
        fgets(key,(int) 50, stdin);

        // Remove newline from input
        if ((newlineposition = strchr(key, '\n')) != NULL) {
            *newlineposition = '\0';
        }
        // Error check the key to make sure its only letters
        for (p = key; *p != '\0'; p++) {
            if(!isalpha(*p)) {
                printf("Error: bad key, invalid char!");
                exit(EXIT_FAILURE);
            }
        }
        // Print plaintext input
        printf("\nPlaintext:\n%s\n", input);

        // Print encrypted text
        enret = vigen_encrypt(input,key);
        printf("\nCiphertext:\n%s\n",enret);


        freq_analysis(enret, freqarray);

        // Print decrypted ciphertext
        deret = vigen_decrypt(enret,key);
        printf("\nDecrypted plaintext:\n%s\n",deret);

        // Print frequency analysis
        printf("\nFrequency Analysis:\n");

        for (c = 'A'; c <= 'Z'; ++c) {      // Print formatted alphabet
            printf("%10c", c);
        }

        printf("\n");
        for (int i = 0; i < 26; i++) {
            printf("%10.1f", freqarray[i]);     // Print formatted occurrence table
        }
                                                // Free memory now that we are done
    }

    return(0);
}