import lief
import os

import pefile

# import extractFeature
import extract
import pickle

#删除不能正常解析的文件

mal_path = "samples/benign"
beni_path = "samples/malicious"

files = os.listdir(mal_path)
count = 0
temp = []
num = 1
for f in files:
    if num % 100 == 0: print(num)
    num += 1
    try:
        extract.extract(mal_path + "/" + f)
    except:
        print("----------------remove {} {}".format(count, f))
        os.remove(mal_path + "/" + f)
        temp.append(f)
        count += 1
print(temp)  # remove的文件名
print(count)  # remove的文件数量

files = os.listdir(beni_path)
count = 0
temp = []
num = 1
for f in files:
    if num % 100 == 0: print(num)
    num += 1
    try:
        extract.extract(beni_path + "/" + f)
        # pefile.PE(mal_path + "/" + f).sections
    except:
        print("----------------remove {} {}".format(count, f))
        os.remove(beni_path + "/" + f)
        temp.append(f)
        count += 1
print(temp)  # remove的文件名
print(count)  # remove的文件数量
