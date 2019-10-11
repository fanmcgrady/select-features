import csv
import os

import pefile

import extract_parser_features
from utility import classifier

MAL_PATH = "samples/malicious"
BENI_PATH = "samples/benign"


# 读取csv
def load_csv(data_path):
    data = []

    with open(data_path) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            for i in range(len(row)):
                if row[i] == 'True':
                    row[i] = True
                elif row[i] == 'False':
                    row[i] = False
                else:
                    row[i] = int(row[i])
            data.append(row)
    return data


# 保存csv
def save_csv(data_path, data):
    if os.path.exists(data_path):
        os.remove(data_path)

    with open(data_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for i in range(len(data)):
            if data[i]:
                writer.writerow(data[i])
    print("save data successfully to: {}".format(data_path))


# 删除不能正常解析的文件
def screen_samples():
    files = os.listdir(MAL_PATH)
    count = 1
    temp = []
    num = 1
    for f in files:
        if num % 1000 == 0: print(num)
        num += 1
        try:
            extract_parser_features.extract(MAL_PATH + "/" + f)
        except:
            print("----------------remove {} {}".format(count, f))
            os.remove(MAL_PATH + "/" + f)
            temp.append(f)
            count += 1
    # print(temp)  # remove的文件名
    print(count)  # remove的文件数量

    files = os.listdir(BENI_PATH)
    count = 1
    temp = []
    num = 1
    for f in files:
        if num % 100 == 0: print(num)
        num += 1
        try:
            extract_parser_features.extract(BENI_PATH + "/" + f)
            # pefile.PE(mal_path + "/" + f).sections
        except:
            print("----------------remove {} {}".format(count, f))
            os.remove(BENI_PATH + "/" + f)
            temp.append(f)
            count += 1
    # print(temp)  # remove的文件名
    print(count)  # remove的文件数量


# 测试某个指标的成功率
def get_features_reward(data_path, feature_index_array):
    # data_path: 样本csv路径
    # feature_index_array: 要选取的指标索引

    data = load_csv(data_path)

    state = []
    for i in range(len(data[0])):
        state.append(0)
    for j in feature_index_array:
        state[j] = 1

    return classifier.get_reward(state, data_path)


# 生成样本文件
def generate_data():
    features = []
    data = []

    files = os.listdir(MAL_PATH)
    count = 1
    for f in files:
        if count % 100 == 0: print("malicious: {}".format(count))
        count += 1
        try:
            features = extract_parser_features.extract(MAL_PATH + "/" + f)
        except:
            print("ERROR: {}".format(f))
        features.append(1)
        if len(features) != 111: print("{}: {}".format(len(features), f))
        data.append(features)

    files = os.listdir(BENI_PATH)
    count = 1
    for f in files:
        if count % 100 == 0: print("benign: {}".format(count))
        count += 1
        try:
            features = extract_parser_features.extract(BENI_PATH + "/" + f)
        except:
            print("ERROR: {}".format(f))
        features.append(0)
        if len(features) != 111: print("{}: {}".format(len(features), f))
        data.append(features)
    return data


# 处理dll字典
def Imported_DLL_and_API(pe):
    dlls = set()
    apis = set()
    try:
        temp = pe.DIRECTORY_ENTRY_IMPORT
    except:
        return dlls, apis

    for i in temp:
        if i.dll: dlls.add(str(i.dll.upper(), encoding="utf8"))
        for j in i.imports:
            if j.name: apis.add(str(j.name.upper(), encoding="utf8"))

    return dlls, apis


# 判断是否有数据目录
def judge_data_directory():
    files = os.listdir(MAL_PATH)
    total = len(files)
    count = 0
    num = 1
    for f in files:
        if num % 1000 == 0: print(num)
        num += 1
        try:
            pe = pefile.PE(MAL_PATH + "/" + f)
            temp = pe.DIRECTORY_ENTRY_RESOURCE
            print("yes: {}".format(temp))
            count += 1
        except:
            print("no")

    print(count / total)

    files = os.listdir(BENI_PATH)
    total = len(files)
    count = 0
    num = 1
    for f in files:
        if num % 1000 == 0: print(num)
        num += 1
        try:
            pe = pefile.PE(BENI_PATH + "/" + f)
            temp = pe.DIRECTORY_ENTRY_RESOURCE
            print("yes".format(temp))
            count += 1
        except:
            print("no")

    print(count / total)
