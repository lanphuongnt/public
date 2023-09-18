import itertools
from Crypto.Util.number import *

# cipher = [0x20, 0x52, 0xb6, 0x89, 0x32, 0xa5, 0x76, 0x03, 0xc1, 0xde, 0xf7, 0xb5, 0x69, 0x4c, 0x8d, 0xa1, 0x69, 0x4c, 0x8d, 0xa1, 0xc3]
# cipher = [0x2e, 0x1d, 0xd6 ,0x7a]
# cipher = [0x17, 0x02, 0x8e, 0xd0, 0x71, 0x5c, 0x86, 0x74, 0x59]
# cipher = [0x02, 0x3d, 0x14, 0xea, 0x10, 0x36, 0x9b]
cipher = [0x45, 0x62, 0xc0, 0xf9, 0x21, 0x78]
out = open("result.txt", "w")
def handle_instruction(ins):
    instruction = ins[:3]
    p1 = ins[8:11]
    if instruction == "not":
        return instruction, p1, "0"
    else:
        p2 = ins[13:-1]
        if p2[-1] == "h":
            p2 = str(int(p2[:-1], 16))
        
        return instruction, p1, p2   
    

def ins_not(p1):
    return (~p1) & 0xFFFFFFFF

def add(p1, p2):
    return (p1 + p2) & 0xFFFFFFFF 

def sub(p1, p2):
    return (p1 - p2) & 0xFFFFFFFF

def xor(p1, p2):
    return (p1 ^ p2) & 0xFFFFFFFF 

def ror(p1, p2):
    return ((p1 << (32 - p2)) | (p1 >> p2)) & 0xFFFFFFFF


def rol(p1, p2):
    return ((p1 >> (32 - p2)) | (p1 << p2)) & 0xFFFFFFFF
    
def chua_biet_ten_gi(p1):
    p2 = p1
    p2 &= 0x0FF00FF00
    p1 &= 0x0FF00FF
    p1 <<= 8
    p2 >>= 8
    p1 |= p2
    return p1 & 0xFFFFFFFF   

def call_reverse_instruction(raw_ins, value):
    ins, p1, p2 = handle_instruction(raw_ins)
    if ins == "not":
        return ins_not(value), 1
    elif ins == "add":
        return sub(value, int(p2)), 1
    elif ins == "sub":
        return add(value, int(p2)), 1
    elif ins == "xor":
        return xor(value, int(p2)), 1
    elif ins == "ror":
        return rol(value, int(p2)), 1
    elif ins == "rol":
        return ror(value, int(p2)), 1
    else:
        return chua_biet_ten_gi(value), 6

def call_instruction(raw_ins, value):
    ins, p1, p2 = handle_instruction(raw_ins)
    if ins == "not":
        return ins_not(value), 1
    elif ins == "add":
        return add(value, int(p2)), 1
    elif ins == "sub":
        return sub(value, int(p2)), 1
    elif ins == "xor":
        return xor(value, int(p2)), 1
    elif ins == "ror":
        return ror(value, int(p2)), 1
    elif ins == "rol":
        return rol(value, int(p2)), 1
    else:
        return chua_biet_ten_gi(value), 6

def reverse_func(stt, value):
    file = "func" + str(stt) + ".txt"
    f0 = open(file, "r")
    all_ins = f0.readlines()
    rip = len(all_ins) - 1
    while rip >= 0:
        value, jmp = call_reverse_instruction(all_ins[rip], value)
        rip -= jmp
    return value


def func(stt, value):
    file = "func" + str(stt) + ".txt"
    f0 = open(file, "r")
    all_ins = f0.readlines()
    rip = 0
    while rip < len(all_ins):
        value, jmp = call_instruction(all_ins[rip], value)
        rip += jmp
    return value

def brute_force():
    permu = list(itertools.permutations([0, 1, 2, 3, 4]))
    for case in permu:
        ct = cipher.copy()
        while len(ct) % 4 != 0:
            ct.append(0)
        # Khuc nay phai brute force 256 ki tu cho moi ki tu con thieu. Nhung ma minh luoi code qua huhu nen minh lay tieu chuan length cua input chia het cho 4 nhe :3
        for stt in case:
            for i in range(0, len(ct), 4):
                val = ct[i + 3] * 0x1000000 + ct[i + 2] * 0x10000 + ct[i + 1] * 0x100 + ct[i]
                tmp = long_to_bytes(reverse_func(stt, val))
                while (len(tmp) % 4 != 0):
                    tmp = b'\x00' + tmp
                ct[i] = tmp[3]
                ct[i + 1] = tmp[2]
                ct[i + 2] = tmp[1]
                ct[i + 3] = tmp[0]
        flag = b""
        for c in ct:
            flag += long_to_bytes(c)
        print(flag, file=out)


# brute_force()
# for fg in list_flag:
#     print(fg, file=out)


# test = 71
# test = func(0, test)
# print(test)
# test = func(1, test)
# print(test)
# test = func(2, test)
# print(test)
# test = func(3, test)
# print(test)
# test = func(4, test)
# print(test)
# # test = reverse_func(4, test)
# # print(test)
# # test = reverse_func(3, test)
# # print(test)
# # test = reverse_func(2, test)
# # print(test)
# # test = reverse_func(1, test)
# # print(test)
# # test = reverse_func(0, test)
# # print(test)

# def bruteone():
#     permu = list(itertools.permutations([0, 1, 2, 3, 4]))
#     cnt = 0
#     for case in permu:
#         cnt += 1
#         print(cnt,":", case)
#         ct = 0xea
#         for stt in case:
#             ct = reverse_func(stt, ct)
#         print(cnt, "-", long_to_bytes(ct), file=out)
        
# # bruteone()


# test = 1718378855
# print(test)
# test = func(0, test)
# print(test)
# test = func(1, test)
# print(test)
# test = func(2, test)
# print(test)
# test = func(3, test)
# print(test)
# test = func(4, test)
# print(test, '\n')


# test = 0x92553fce
# print(test)
# test = reverse_func(4, test)
# print(test)
# test = reverse_func(3, test)
# print(test)
# test = reverse_func(2, test)
# print(test)
# test = reverse_func(1, test)
# print(test)
# test = reverse_func(0, test)
# print(test)



def dotest():
    permu = list(itertools.permutations([0, 1, 2, 3, 4]))
    cnt = 0
    for case in permu:
        cnt += 1
        print(cnt,":", case)
        ct = [0x6c, 0x6d, 0x61, 0x6f, 0x7b, 0x7d]
        while len(ct) % 4 != 0:
            ct.append(0)
        for stt in case:
            # print(stt)
            for i in range(0, len(ct), 4):
                val = ct[i + 3] * 0x1000000 + ct[i + 2] * 0x10000 + ct[i + 1] * 0x100 + ct[i]
                # print(hex(val))
                tmp = long_to_bytes(func(stt, val))
                while (len(tmp) % 4 != 0):
                    tmp = b'\x00' + tmp
                ct[i] = tmp[3]
                ct[i + 1] = tmp[2]
                ct[i + 2] = tmp[1]
                ct[i + 3] = tmp[0]
                
        flag = b""
        for c in ct:
            flag += long_to_bytes(c)
        # flag = flag[:len(cipher)]
        print(flag.hex(), file=out)

            
dotest()