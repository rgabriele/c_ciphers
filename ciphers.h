// USE C90 STANDARD PLEASE
// Riley Gabriele
// 250921157
// CS2211 ASN 4

#ifndef CIPHERS_MAIN_CIPHERS_H
#define CIPHERS_MAIN_CIPHERS_H

char * caesar_encrypt(char *plaintext, int key);

char * caesar_decrypt(char *ciphertext, int key);

char * vigen_encrypt(char *plaintext, char *key);

char * vigen_decrypt(char *ciphertext, char *key);

void freq_analysis(char *ciphertext, double letters[26]);

#endif //CIPHERS_MAIN_CIPHERS_H
