import argparse
import os

import extract_n_gram
import utils
from extract import Extract

# linux命令行使用，输入以下命令即可使用
# nohup python generate_data.py --n-grams 4 --top-num 400 --result-name training_data_4grams.csv>generate_log.txt 2>&1 &
parser = argparse.ArgumentParser()
parser.add_argument('--n-grams', type=int, default=4)
parser.add_argument('--top-num', type=int, default=400)
parser.add_argument('--result-name', type=str, default='training_data_4grams.csv')
args = parser.parse_args()

# 训练样本路径
paths = [utils.BENI_PATH, utils.MAL_PATH]
# 滑动窗口长度
N = args.n_grams
# 选取的特征数
top_num = args.top_num
# 用于统计样本文件的总数
sum_of_file = 0
# 用于暂存写入csv文件的每个文件的特征
data = []
# 用于存储训练样本中出现频率最高的200个字节码特征的字典
topnum_byte_feature_dict = {}
# 用于存储训练样本中出现频率最高的200个操作码特征的字典
topnum_op_feature_dict = {}
# 统计出现了某些字节码特征的文件数量
count_byte_feature_dict = {}
# 统计出现了某些操作码特征的文件数量
count_op_feature_dict = {}

# 计算样本文件的总数
for path in paths:
    file_list = os.listdir(path)
    sum_of_file += len(file_list)

# 计算字节码和操作码在样本中出现的频率，以及统计出现了某些操作码和字节码的文件数量
topnum_byte_feature_dict, count_byte_feature_dict = extract_n_gram.count_byte_DF(paths, N, top_num)
# topnum_op_feature_dict, count_op_feature_dict = extract_n_gram.count_op_DF(paths, N, top_num)


# 生成一个extract对象用于提取特征
extract = Extract(sum_of_file, topnum_byte_feature_dict, count_byte_feature_dict, topnum_op_feature_dict=None,
                  count_op_feature_dict=None, N=4)

# 处理正常样本
files = os.listdir(utils.BENI_PATH)
count = 1

for f in files:
    features = []
    if count % 10 == 0:
        print("benign: {}".format(count))
    count += 1
    # 第一个位置为文件名
    # features.append(f)
    try:
        # 调用extract对象去处理正常样本文件
        features.extend(extract(utils.BENI_PATH + "/" + f))
    except Exception as e:
        print("ERROR: {} {}".format(f, e))
    features.append(0)
    data.append(features)

# 处理恶意文件
files = os.listdir(utils.MAL_PATH)
count = 1

for f in files:
    features = []
    if count % 10 == 0:
        print("malicious: {}".format(count))
    count += 1
    # 第一个位置为文件名
    # features.append(f)
    try:
        # 调用extract对象去处理恶意样本文件
        features.extend(extract(utils.MAL_PATH + "/" + f))
    except Exception as e:
        print("ERROR: {} {}".format(f, e))
    # 打上标签
    features.append(1)
    data.append(features)

# 在data文件夹中生成我们训练要用的csv文件
utils.save_csv('data/' + args.result_name, data)
