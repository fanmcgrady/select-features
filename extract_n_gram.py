import binascii
import math
import os

from capstone import *


def extract(file, sum_of_file, topnum_byte_feature_dict, count_byte_feature_dict, topnum_op_feature_dict=None,
            count_op_feature_dict=None, N=4):
    # n-grams特征列表
    features = []
    # 将PE文件的字节码特征提取并加入，是一个1Xtop_num的一维向量
    features.extend(count_byte_TF_plus_IDF(file, sum_of_file, topnum_byte_feature_dict, count_byte_feature_dict, N))
    # 将PE文件的操作码特征提取并加入，也是一个1Xtop_num的一维向量
    # features.extend(count_op_TF_plus_IDF(file, sum_of_file, topnum_op_feature_dict, count_op_feature_dict, N))
    return features


# 用于计算在所有文件中的所有n-grams字节码短序列出现的次数（文档频率），以及统计出现某些频率的文件数
def count_byte_DF(paths, N, top_num):
    # 存放数据集中各个出现过的短序列的次数
    all_feature_dict = {}
    # 存放最高出现次数的top_num个短序列
    topnum_feature_dict = {}
    # 用于统计出现某些频率的文件数
    count_feature_dict = {}

    for path in paths:
        file_list = os.listdir(path)
        for file in file_list:
            # 用于存放当前文件中出现了哪些n-grams特征，不重复计数
            temp_feature_dict = {}
            with open(os.path.join(path, file), 'rb') as cur_file:
                byte = cur_file.read()
                hex_string = str.upper(binascii.b2a_hex(byte).decode('ascii'))
            cur = 0
            while (cur <= len(hex_string) - N):
                # 用大小为N的滑动窗口扫描，截取大小为N的特征
                temp = hex_string[cur:cur + N]
                # 存入字典
                if all_feature_dict.get(temp):
                    all_feature_dict[temp] += 1
                else:
                    all_feature_dict[temp] = 1
                # 如果当前的n-grams特征在这个文件中没有出现过，那么统计
                if temp not in temp_feature_dict.keys():
                    temp_feature_dict[temp] = 1
                cur += 1
            # 将当前文件的特征统计加到全部文件的特征统计字典中
            for key in temp_feature_dict.keys():
                if count_feature_dict.get(key):
                    count_feature_dict[key] += temp_feature_dict[key]
                else:
                    count_feature_dict[key] = temp_feature_dict[key]

    sorted_dict = sorted(all_feature_dict.items(), key=lambda x: x[1], reverse=True)
    sorted_dict = sorted_dict[:top_num]
    # 将特征字典返回，形式是{feature1:0, feature2:0, .....}，用于单个文件统计
    for feature in sorted_dict:
        topnum_feature_dict[feature[0]] = 0
    return topnum_feature_dict, count_feature_dict


# 计算TF值，即：用于计算字节码短序列在某个文件中出现的频率
def count_byte_TF(file, N):
    tf_dict = {}
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        # 转换成16进制的串表示
        hex_string = str.upper(binascii.b2a_hex(byte).decode('ascii'))
    cur = 0
    # 统计出现过的短字符次数，重复计数，如AE30的短序列之前出现过，这次也要计数
    count = 0
    while (cur <= len(hex_string) - N):
        # 用大小为N的滑动窗口扫描，截取大小为N的特征
        temp = hex_string[cur:cur + N]
        # 计数加1
        count += 1
        # 存入字典
        if tf_dict.get(temp):
            tf_dict[temp] += 1
        else:
            tf_dict[temp] = 1
        # 滑动窗口后移一步
        cur += 1
    for key in tf_dict.keys():
        tf_dict[key] /= count
    return tf_dict


# 计算IDF值，即：用于计算出现某个字节码短序列的文件在所有文件中的比值倒数的对数值
# log(D/d)  D为总文件数，d为出现了某个字节码短序列的文件总数
def count_byte_IDF(pattern, sum_of_file, topnum_feature_dict, count_feature_dict):
    # 如果在最终选择的特征库中存在该短序列，则查看字典取出出现频数
    if pattern in topnum_feature_dict.keys():
        d = count_feature_dict[pattern]
    else:
        return 0
    return math.log(sum_of_file / d)


# 用于计算单个文件在特征字典中的所有字节码短序列的TF*IDF的值
# 作为后续分类的特征
def count_byte_TF_plus_IDF(file, sum_of_file, topnum_feature_dict, count_feature_dict, N):
    feature = []
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
    cur = 0
    # 必须先扫描一次该文件，统计该文件中每个字节码短序列出现的频率
    tf_dict = count_byte_TF(file, N)
    while cur <= len(hex) - N:
        temp = hex[cur:cur + N]
        if temp in topnum_feature_dict.keys():
            TF = tf_dict.get(temp)
            IDF = count_byte_IDF(temp, sum_of_file, topnum_feature_dict, count_feature_dict)
            topnum_feature_dict[temp] = TF * IDF
            cur += 1
        else:
            cur += 1
    for val in topnum_feature_dict.values():
        # 一个长度为1Xtop_num的列表
        feature.append(val)
    return feature


# 用于计算在所有文件中的所有n-grams操作码短序列出现的次数（文档频率）
def count_op_DF(paths, N, top_num):
    # 存放数据集中各个出现过的短序列的次数
    all_feature_dict = {}
    # 存放最高出现次数的top_num个短序列
    topnum_feature_dict = {}
    # 用于统计出现某些频率的文件数
    count_feature_dict = {}
    # 初始化一个反汇编对象，传入字节码，可以得到汇编指令
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for path in paths:
        file_list = os.listdir(path)
        for file in file_list:
            # 用于存放出现过的操作码特征，方便后面操作
            op_list = []
            # 用于存放当前文件中出现了哪些n-grams特征，不重复计数
            temp_feature_dict = {}
            with open(os.path.join(path, file), 'rb') as cur_file:
                byte = cur_file.read()
                hex = binascii.b2a_hex(byte)
                for op in md.disasm(hex, 0x00):
                    op_list.append(op.mnemonic)
            cur = 0
            while (cur <= len(op_list) - N):
                # 用大小为N的滑动窗口扫描，截取大小为N的特征
                # 如N=3，那么特征可以是['pop', 'pop', 'push']
                temp = op_list[cur:cur + N]
                # 用空格连接，变成 'pop pop push'型的字符串序列，存入字典
                temp = ' '.join(temp)
                # 存入字典
                if all_feature_dict.get(temp):
                    all_feature_dict[temp] += 1
                else:
                    all_feature_dict[temp] = 1
                # 如果当前的n-grams特征在这个文件中没有出现过，那么统计
                if temp not in temp_feature_dict.keys():
                    temp_feature_dict[temp] = 1
                cur += 1
            # 将当前文件的特征统计加到全部文件的特征统计字典中
            for key in temp_feature_dict.keys():
                if count_feature_dict.get(key):
                    count_feature_dict[key] += temp_feature_dict[key]
                else:
                    count_feature_dict[key] = temp_feature_dict[key]
        sorted_dict = sorted(all_feature_dict.items(), key=lambda x: x[1], reverse=True)
        sorted_dict = sorted_dict[:top_num]
        # 将特征字典返回，形式是{feature1:0, feature2:0, .....}，用于单个文件统计
        for feature in sorted_dict:
            topnum_feature_dict[feature[0]] = 0
    return topnum_feature_dict, count_feature_dict


# 计算TF值，即：用于计算操作码短序列在某个文件中出现的频率
def count_op_TF(file, N):
    tf_dict = {}
    # 用于存储某个文件的操作码序列
    op_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        hex = binascii.b2a_hex(byte)
        for op in md.disasm(hex, 0x00):
            op_list.append(op.mnemonic)
    cur = 0
    # 统计出现过的短字符次数，重复计数，如AE30的短序列之前出现过，这次也要计数
    count = 0
    while (cur <= len(op_list) - N):
        # 用大小为N的滑动窗口扫描，截取大小为N的特征
        temp = op_list[cur:cur + N]
        # 用空格连接，变成形如'pop pop push'型的字符串序列，存入字典
        temp = ' '.join(temp)
        # 计数加1
        count += 1
        # 存入字典
        if tf_dict.get(temp):
            tf_dict[temp] += 1
        else:
            tf_dict[temp] = 1
        # 滑动窗口后移一步
        cur += 1
    for key in tf_dict.keys():
        tf_dict[key] /= count
    return tf_dict


# 计算IDF值，即：用于计算出现某个操作码短序列的文件在所有文件中的比值倒数的对数值
# log(D/d)  D为总文件数，d为出现了某个操作码短序列的文件总数
def count_op_IDF(pattern, sum_of_file, topnum_feature_dict, count_feature_dict):
    # 如果在最终选择的特征库中存在该操作码短序列，则查看字典取出出现次数
    if topnum_feature_dict.get(pattern):
        d = count_feature_dict[pattern]
    else:
        d = 0
    return math.log((sum_of_file / d))


# 用于计算单个文件在特征字典中的所有操作码短序列的TF*IDF的值
# 作为后续分类的特征
def count_op_TF_plus_IDF(file, sum_of_file, topnum_feature_dict, count_feature_dict, N):
    feature = []
    op_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        hex = binascii.b2a_hex(byte)
        for op in md.disasm(hex, 0x00):
            op_list.append(op.mnemonic)
    cur = 0
    # 必须先扫描一次该文件，统计该文件中每个操作码短序列出现的频率
    tf_dict = count_op_TF(file, N)
    while cur <= len(op_list) - N:
        temp = op_list[cur:cur + N]
        temp = ' '.join(temp)
        if temp in topnum_feature_dict.keys():
            TF = tf_dict.get(temp)
            IDF = count_op_IDF(temp, sum_of_file, topnum_feature_dict, count_feature_dict)
            topnum_feature_dict[temp] = TF * IDF
        else:
            continue
        cur += 1
    for val in topnum_feature_dict.values():
        # 一个长度为1Xtop_num的列表
        feature.append(val)
    return feature
