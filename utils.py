import csv
import os

from generate_data import extract_parser_features
from utility.classifier import get_reward

MAL_PATH = "samples/benign"
BENI_PATH = "samples/malicious"


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


# 测试单个指标
# data_path: 样本csv路径
# feature_index_array: 要选取的指标索引
def test_single_features(data_path, feature_index_array):
    data = load_csv(data_path)

    state = []
    for i in range(len(data)):
        state.append(0)
    for j in feature_index_array:
        state[j] = 1

    return get_reward(state, data_path)


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
