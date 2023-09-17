# Writeup

## OLD BUT GOLD

Đầu tiên mình chạy thử file main, nhập thử cái gì đó thì chương trình hiện ra 2 messages là `Wrong length!!.` và `nope!`

![image](https://github.com/lanphuongnt/public/assets/117977667/25f5cc8f-aa1e-4499-be6e-55eb49fa8ffd)


Mình tìm thử thì thấy đoạn chương trình này:
```C
int case_25()
{
  int result; // eax

  result = read(0, byte_6080, 32uLL);
  if ( (_WORD)result != 32 )
    return puts("Wrong length!!.");
  return result;
}
```
Trong đoạn này sẽ đọc vào `byte_6080` và kiểm tra xem độ dài có bằng `32` hay không.

Quay lại hàm main, thì mình thấy để chương trình trả về `congratulation!` thì kết quả trả về của hàm `sub_1B08` phải khác `0`.


```C
int main()
{
    int v4[1002];
    unsigned __int64 v5;

    v5 = __readfsqword(0x28u);
    memset(v4, 0, 0xFA0uLL);
    v4[0] = 13;
    v4[1] = 3;
    v4[2] = 512;
    ...
    v4[480] = 1;
    v4[481] = 255;
    if ( (unsigned int)sub_1B08((__int64)v4) )
        puts("congratulation!");
    else
        puts("nope!");
    return 0;
}
```

Xem qua hàm `sub_1B08` thì mình thấy, với mỗi 4 phần tử liên tiếp của `v4` tương đương 1 lệnh, phần tử đầu tiên là instruction, 3 phần tử tiếp theo là tham số. Ví dụ:

```C
void case_10(int a1, int a2, unsigned int a3){
    if (a1){
        if (a1 == 1){
            dword_6040[a2] = a3 & dword_6040[a2];
        } 
        else if ( a1 == 2 ){
            byte_6080[a2] &= a3;
        }
    }
    else{
        dword_6040[a2] &= dword_6040[a3];
    }
}
```

`case_10` tương ứng với lệnh `and`. Tương tự với các case khác.

Mình viết chương trình này lại cho dễ hiểu hơn:
```
0		: byte[512] = 100
4		: byte[513] = 105
8		: byte[514] = 103
12		: byte[515] = 105
16		: byte[516] = 116
20		: byte[517] = 97
24		: byte[518] = 108
28		: byte[519] = 95
32		: byte[520] = 100
36		: byte[521] = 114
40		: byte[522] = 97
44		: byte[523] = 103
48		: byte[524] = 111
52		: byte[525] = 110
56		: byte[526] = 95
60		: byte[527] = 103
64		: byte[528] = 108
68		: byte[529] = 111
72		: byte[530] = 98
76		: byte[531] = 97
80		: byte[532] = 108
84		: byte[533] = 95
88		: byte[534] = 98
92		: byte[535] = 97
96		: byte[536] = 110
100		: byte[537] = 95
104		: byte[538] = 104
108		: byte[539] = 97
112		: byte[540] = 104
116		: byte[541] = 97
120		: byte[542] = 104
124		: byte[543] = 97
128		: read input
129		: dword[0] = 0
133		: dword[1] = 0
137		: dword[2] = 0
141		: dword[3] = 0
145		: dword[2] = dword[0]
149		: dword[2] &= 31
153		: dword[2] += 512
157		: dword[2] = byte[dword[2]]
161		: dword[3] = 256
165		: dword[3] += dword[0]
169		: dword[3] = byte[dword[3]]
173		: dword[3] += dword[2]
177		: dword[3] += dword[1]
181		: dword[3] &= 255
185		: dword[1] = dword[3]
189		: dword[3] += 256
193		: dword[4] = 256
197		: dword[4] += dword[0]
201		: swap(byte[dword[4]], byte[dword[3]])
204		: dword[0] += 1
208		: if dword[0] == 256: 
212		: jmp 214 else jmp 145
214		: byte[1024] = 180
218		: byte[1025] = 137
222		: byte[1026] = 186
226		: byte[1027] = 155
230		: byte[1028] = 166
234		: byte[1029] = 223
238		: byte[1030] = 214
242		: byte[1031] = 254
246		: byte[1032] = 103
250		: byte[1033] = 53
254		: byte[1034] = 156
258		: byte[1035] = 235
262		: byte[1036] = 86
266		: byte[1037] = 72
270		: byte[1038] = 39
274		: byte[1039] = 230
278		: byte[1040] = 18
282		: byte[1041] = 219
286		: byte[1042] = 120
290		: byte[1043] = 48
294		: byte[1044] = 102
298		: byte[1045] = 32
302		: byte[1046] = 81
306		: byte[1047] = 160
310		: byte[1048] = 10
314		: byte[1049] = 219
318		: byte[1050] = 146
322		: byte[1051] = 131
326		: byte[1052] = 158
330		: byte[1053] = 184
334		: byte[1054] = 64
338		: byte[1055] = 191
342		: dword[0] = 0
346		: dword[1] = 0
350		: dword[2] = 0
354		: dword[3] = 0
358		: dword[6] = 0
362		: dword[0] += 1
366		: dword[0] &= 255
370		: dword[2] = dword[0]
374		: dword[2] += 256
378		: dword[2] = byte[dword[2]]
382		: dword[2] += dword[1]
386		: dword[2] &= 255
390		: dword[1] = dword[2]
394		: dword[3] = dword[0]
398		: dword[2] += 256
402		: dword[3] += 256
406		: swap(byte[dword[3]], byte[dword[2]])
409		: dword[4] = byte[dword[2]]
413		: dword[5] = byte[dword[3]]
417		: dword[4] += dword[5]
421		: dword[4] &= 255
425		: dword[4] += 256
429		: dword[4] = byte[dword[4]]
433		: dword[5] ^= dword[5]
437		: dword[5] += dword[6]
441		: dword[5] = byte[dword[5]]
445		: dword[5] ^= dword[4]
449		: dword[4] = 1024
453		: dword[4] += dword[6]
457		: dword[4] = byte[dword[4]]
461		: if dword[4] == dword[5]:
465		: jmp 467 else jmp 481
467		: dword[6] += 1
471		: if dword[6] == 32: 
475		: jmp 477 else jmp 362
477		: dword[8] = 1
```

Tiếp tục viết lại đoạn trên ): 

```C
#include <stdio.h>
#include <string.h>

void swap(unsigned char *a, unsigned char *b){
    int tmp = *a;
    *a = *b;
    *b = tmp;
}
unsigned char byte[10000];
int dword[9];
int main(){
    memset(byte, 0, sizeof(byte));
    memset(dword, 0, sizeof(dword));
    for (int i = 0; i <= 255; i++){
        byte[i + 256] = i;
    }
    byte[512] = 100;
    byte[513] = 105;
    byte[514] = 103;
    byte[515] = 105;
    byte[516] = 116;
    byte[517] = 97;
    byte[518] = 108;
    byte[519] = 95;
    byte[520] = 100;
    byte[521] = 114;
    byte[522] = 97;
    byte[523] = 103;
    byte[524] = 111;
    byte[525] = 110;
    byte[526] = 95;
    byte[527] = 103;
    byte[528] = 108;
    byte[529] = 111;
    byte[530] = 98;
    byte[531] = 97;
    byte[532] = 108;
    byte[533] = 95;
    byte[534] = 98;
    byte[535] = 97;
    byte[536] = 110;
    byte[537] = 95;
    byte[538] = 104;
    byte[539] = 97;
    byte[540] = 104;
    byte[541] = 97;
    byte[542] = 104;
    byte[543] = 97;

    read(0, byte, 32uLL);


    int tmp = 0;
    for (int i = 0; i < 256; i++){
        int aKey = byte[(i & 31) + 512]; // lap lai key
        int index = (byte[256 + i] + aKey + tmp) & 255;
        tmp = index;
        swap(&byte[index + 256], &byte[i + 256]);
    }
    byte[1024] = 180;
    byte[1025] = 137;
    byte[1026] = 186;
    byte[1027] = 155;
    byte[1028] = 166;
    byte[1029] = 223;
    byte[1030] = 214;
    byte[1031] = 254;
    byte[1032] = 103;
    byte[1033] = 53;
    byte[1034] = 156;
    byte[1035] = 235;
    byte[1036] = 86;
    byte[1037] = 72;
    byte[1038] = 39;
    byte[1039] = 230;
    byte[1040] = 18;
    byte[1041] = 219;
    byte[1042] = 120;
    byte[1043] = 48;
    byte[1044] = 102;
    byte[1045] = 32;
    byte[1046] = 81;
    byte[1047] = 160;
    byte[1048] = 10;
    byte[1049] = 219;
    byte[1050] = 146;
    byte[1051] = 131;
    byte[1052] = 158;
    byte[1053] = 184;
    byte[1054] = 64;
    byte[1055] = 191;
    memset(dword, 0, sizeof (dword));
    tmp = 0;
    for (int i = 0; i < 32; i++){
        int j = (i + 1) & 255;
        int index = (byte[j + 256] + tmp) & 255;
        tmp = index;
        int index2 = 256 + j;
        index = index + 256;
        swap(&byte[index], &byte[index2]);

        dword[4] = byte[((byte[index] + byte[index2]) & 255) + 256];
        dword[5] = byte[i] ^ dword[4];    
        dword[4] = byte[i + 1024];
        /*
            Đoạn này lấy input xor với dword[4] rồi so sánh với byte[1024 + i].
            Vì vậy để có input mình lấy byte[1024 + i] xor với giá trị dword[4].
            byte[i] = byte[((byte[index] + byte[index2]) & 255) + 256] ^ byte[i + 1024]);
        */
        
        if (dword[4] == dword[5]){
            continue;           
        }
        else{
            return 0;
        }
    }
    dword[8] = 1;
    return dword[8];
}
```

`Flag: W1{happy_happy_easy_babyvm!!!!!}`

*Note* 
Sau khi ngồi viết lại tiếp cái đoạn code trên thì mình thấy đây là thuật toán mã hóa RC4.

Link tham khảo: https://www.geeksforgeeks.org/rc4-encryption-algorithm/
```C
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
    int index = 0;
    for (int i = 0; i < 256; i++){
        index = (s[i] + key[i & 31] + index) & 255;
        swap(&s[index], &s[i]);
    }
}

void decrypt(unsigned char* cipher){
    if (strlen(cipher) != 32){
        puts("Poor u :(");
    }
    int index = 0;
    unsigned char plaintext[33];
    for (int i = 0; i < 32; i++){
        index = (s[(i + 1) & 255] + index) & 255;
        swap(&s[index], &s[(i + 1) & 255]);
        plaintext[i] = cipher[i] ^ s[(s[index] + s[(i + 1) & 255]) & 255];
    }
    printf("%s", plaintext);
}

int main(){
    dost();
    decrypt(ciphertext);
    return 0;
}
```








