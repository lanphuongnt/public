#include <stdio.h>
#include <string.h>

unsigned char key[] = "digital_dragon_global_ban_hahaha";
unsigned char ciphertext[] = {180, 137, 186, 155, 166, 223, 214, 254, 103, 53, 156, 235, 86, 72, 39, 230, 18, 219, 120, 48, 102, 32, 81, 160, 10, 219, 146, 131, 158, 184, 64, 191, 0};
unsigned char s[256];

void swap(unsigned char *a, unsigned char *b){
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void dost(){
    for (int i = 0; i < 256; i++){
        s[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++){
        j = (s[i] + key[i & 31] + j) & 255;
        swap(&s[j], &s[i]);
    }
}

void decrypt(unsigned char* cipher){
    if (strlen(cipher) != 32){
        puts("Poor u :(");
    }
    int j = 0;
    unsigned char plaintext[33];
    for (int i = 0; i < 32; i++){
        j = (s[(i + 1) & 255] + j) & 255;
        swap(&s[j], &s[(i + 1) & 255]);
        plaintext[i] = cipher[i] ^ s[(s[j] + s[(i + 1) & 255]) & 255];
    }
    printf("%s", plaintext);
}

int main(){
    dost();
    decrypt(ciphertext);
    return 0;
}


