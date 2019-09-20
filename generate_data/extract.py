import pickle
import pefile
import binascii
import os
import math

# 解析pe文件，提取相应指标
with open("intersection-top20.pkl", 'rb') as f:
    dll_dict = pickle.load(f)


# with open("selected api dict.pkl", 'rb') as f:
#     api_dict = pickle.load(f)


def extract(file):
    mal_path = "samples/malicious"
    beni_path = "samples/benign"
    paths = [mal_path, beni_path]
    # n-grams窗口大小
    N = 4
    # 保留前top_num个的特征
    top_num = 200
    # 计算所有短序列的词频,以及出现次数最高的前top_num个短序列
    topnum_feature_dict, all_feature_dict = countDF(paths, N, top_num)

    # 统计文件总数
    sum_of_file = 0
    for path in paths:
        file_list = os.listdir(path)
        sum_of_file += len(file_list)

    pe = pefile.PE(file)

    features = Dos_Header(pe)
    # print(len(features))
    features.extend(File_Header(pe))
    # print(len(features))
    features.extend(Optional_Header(pe))
    # print(len(features))
    features.extend(Data_Directory(pe))
    # print(len(features))
    features.extend(Sections(pe))
    # print(len(features))
    features.extend(Resources(pe))
    # print(len(features))
    features.extend(Imported_DLL_and_API(pe))
    # print(len(features))
    features.extend(countTFplusIDF(file, sum_of_file, topnum_feature_dict,all_feature_dict, N))

    return features


# DOS 头部，15个指标，选取该部分除了保留字之外的所有属性
def Dos_Header(pe):
    features = []

    temp = pe.DOS_HEADER
    # features.append(temp.e_magic)  # 1 固定值'MZ'(是为了纪念MS-DOS的最初创建者Mark Zbikowski)，不选取
    features.append(temp.e_cblp)  # 2
    features.append(temp.e_cp)  # 3
    features.append(temp.e_crlc)  # 4
    features.append(temp.e_cparhdr)  # 5
    features.append(temp.e_minalloc)  # 6
    features.append(temp.e_maxalloc)  # 7
    features.append(temp.e_ss)  # 8
    features.append(temp.e_sp)  # 9
    features.append(temp.e_csum)  # 10
    features.append(temp.e_ip)  # 11
    features.append(temp.e_cs)  # 12
    features.append(temp.e_lfarlc)  # 13
    # features.append(temp.e_res) # 保留字，不选取
    features.append(temp.e_oemid)  # 14
    features.append(temp.e_oeminfo)  # 15
    # features.append(temp.e_res2) # 保留字，不选取
    features.append(temp.e_lfanew)  # 16

    # print(len(features))
    return features


# File Header，7个指标
def File_Header(pe):
    features = []

    temp = pe.FILE_HEADER

    features.append(temp.Machine)  # 17 运行平台
    features.append(temp.NumberOfSections)  # 18 文件的区块数目
    # features.append(temp.TimeDateStamp)  # 19 文件创建日期和时间 不选取
    features.append(temp.PointerToSymbolTable)  # 20 指向符号表（用于调试）
    features.append(temp.NumberOfSymbols)  # 21 符号表中符号个数（用于调试）
    features.append(temp.SizeOfOptionalHeader)  # 22 IMAGE_OPTIONAL_HEADER32结构大小
    features.append(temp.Characteristics)  # 23 文件属性

    # 该部分提供的节数是否等于真实节数，等于则值为 1，否则为0
    if temp.NumberOfSections == len(pe.sections):  # 24
        features.append(1)
    else:
        features.append(0)
    return features


# Optional Header，29个指标，选择该部分的所有属性
def Optional_Header(pe):
    features = []
    temp = pe.OPTIONAL_HEADER

    features.append(temp.Magic)  # 25 标志字, ROM 映像（0107h）,普通可执行文件（010Bh）
    features.append(temp.MajorLinkerVersion)  # 26 链接程序的主版本号
    features.append(temp.MinorLinkerVersion)  # 27 链接程序的次版本号
    features.append(temp.SizeOfCode)  # 28 所有含代码的节的总大小
    features.append(temp.SizeOfInitializedData)  # 29 所有含已初始化数据的节的总大小
    features.append(temp.SizeOfUninitializedData)  # 30 所有含未初始化数据的节的大小
    features.append(temp.AddressOfEntryPoint)  # 31 程序执行入口RVA
    features.append(temp.BaseOfCode)  # 32 代码的区块的起始RVA
    # features.append(temp.BaseOfData)  # 33 数据的区块的起始RVA 源码显示64位PE文件无该字段，所以不选取
    features.append(temp.ImageBase)  # 33 程序的首选装载地址
    features.append(temp.SectionAlignment)  # 34 内存中的区块的对齐大小
    features.append(temp.FileAlignment)  # 35 文件中的区块的对齐大小
    features.append(temp.MajorOperatingSystemVersion)  # 36 要求操作系统最低版本号的主版本号
    features.append(temp.MinorOperatingSystemVersion)  # 37 要求操作系统最低版本号的副版本号
    features.append(temp.MajorImageVersion)  # 38 可运行于操作系统的主版本号
    features.append(temp.MinorImageVersion)  # 39 可运行于操作系统的次版本号
    features.append(temp.MajorSubsystemVersion)  # 40 要求最低子系统版本的主版本号
    features.append(temp.MinorSubsystemVersion)  # 41 要求最低子系统版本的次版本号
    features.append(temp.Reserved1)  # 42 莫须有字段，不被病毒利用的话一般为0
    features.append(temp.SizeOfImage)  # 43 映像装入内存后的总尺寸
    features.append(temp.SizeOfHeaders)  # 44 所有头 + 区块表的尺寸大小
    features.append(temp.CheckSum)  # 45 映像的校检和
    features.append(temp.Subsystem)  # 46 可执行文件期望的子系统
    features.append(temp.DllCharacteristics)  # 47 DllMain()函数何时被调用，默认为 0
    features.append(temp.SizeOfStackReserve)  # 48 初始化时的栈大小
    features.append(temp.SizeOfStackCommit)  # 49 初始化时实际提交的栈大小
    features.append(temp.SizeOfHeapReserve)  # 50 初始化时保留的堆大小
    features.append(temp.SizeOfHeapCommit)  # 51 初始化时实际提交的堆大小
    features.append(temp.LoaderFlags)  # 52 与调试有关，默认为0
    features.append(temp.NumberOfRvaAndSizes)  # 53 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16

    return features


# 数据目录表，32个指标，保存 16 个目录表的虚拟地址和大小，
# 若某个目录表不存在，则属性全部置为 0
def Data_Directory(pe):
    # 55 - 86
    features = []
    temp = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    count = 0
    for i in temp:
        features.append(i.VirtualAddress)
        features.append(i.Size)
        count += 1
    for m in range(count, 16):
        features.append(0)
        features.append(0)
    # print(len(features))
    return features


# .text 节/.data 节/.rsrc 节，9 * 3 个指标，选择该部分的所有属性
def Sections(pe):
    # 87 - 119
    text = []
    data = []
    rsrc = []
    sections = pe.sections

    for f in sections:
        name = str(f.Name, encoding="utf8").strip('\x00')
        if name == '.text' or name == '.data' or name == '.rsrc':
            list = []
            # list.append(f.Misc) # 与Misc_VirtualSize相同，不选取
            # list.append(f.Misc_PhysicalAddress) # 与Misc_VirtualSize相同，不选取
            list.append(f.Misc_VirtualSize)  # 区块尺寸
            list.append(f.VirtualAddress)  # 区块的RVA地址
            list.append(f.SizeOfRawData)  # 在文件中对齐后的尺寸
            list.append(f.PointerToRawData)  # 在文件中偏移
            list.append(f.PointerToRelocations)  # 在OBJ文件中使用，重定位的偏移
            list.append(f.PointerToLinenumbers)  # 行号表的偏移（供调试使用）
            list.append(f.NumberOfRelocations)  # 在OBJ文件中使用，重定位项数目
            list.append(f.NumberOfLinenumbers)  # 行号表中行号的数目
            list.append(f.Characteristics)  # 区块属性如可读，可写，可执行等

            if name == '.text':
                text = list
            elif name == '.dara':
                data = list
            else:
                rsrc = list

    if len(text) == 0:
        for i in range(9):
            text.append(0)
    if len(data) == 0:
        for i in range(9):
            data.append(0)
    if len(rsrc) == 0:
        for i in range(9):
            rsrc.append(0)

    text.extend(data)
    text.extend(rsrc)

    return text


##################################
# 一下两部分指标是否合适，有待探讨


# 资源目录表，22个指标，选择调用的资源的个数，
# 并选取 id 属于{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 17, 19, 20, 21, 22, 23, 24}的资源调用的 entry 个数
def Resources(pe):
    # 120 - 141
    features = []
    # print(len(features))
    types = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 16, 17, 19, 20, 21, 22, 23, 24]
    try:
        temp = pe.DIRECTORY_ENTRY_RESOURCE
    except:
        features.append(0)
        for i in types:
            features.append(0)
        return features
    # print(len(features))
    features.append(temp.struct.NumberOfNamedEntries + temp.struct.NumberOfIdEntries)
    for i in types:
        exist = False
        for x in temp.entries:
            if x.id == i:
                features.append(x.directory.struct.NumberOfNamedEntries + x.directory.struct.NumberOfIdEntries)
                exist = True
                break
        if not exist:
            features.append(0)
    # print(len(features))
    return features


# 导入的 DLL，20个指标，选择与软件安全可能相关和信息增益较大的 20 个 DLL
# 导入的 DLL 总数，1个指标，统计该样本导入的 DLL 总数
# 导入的 API 总数，1个指标，统计该样本导入的 API 总数
def Imported_DLL_and_API(pe):
    # 142 - 163
    dlls = []
    apis = []
    try:
        temp = pe.DIRECTORY_ENTRY_IMPORT
    except:
        result = []
        for i in range(22):
            result.append(0)
        return result
    for i in temp:
        if i.dll: dlls.append(str(i.dll.upper(), encoding="utf8"))
        for j in i.imports:
            if j.name: apis.append(str(j.name.upper(), encoding="utf8"))
    dll = []
    api = []

    for key in dll_dict.keys():
        exist = False
        for i in dlls:
            if i == key:
                dll.append(1)
                exist = True
                break
        if not exist:
            dll.append(0)

    # for key in api_dict.keys():
    #     exist = False
    #     for i in apis:
    #         if i == key:
    #             api.append(1)
    #             exist = True
    #             break
    #     if not exist:
    #         api.append(0)

    result = dll
    # result.extend(api)
    result.append(len(dlls))
    result.append(len(apis))

    # print("dll = {}, api = {}".format(len(dll),len(api)))
    # print(len(result))
    return result

# 用于计算在所有文件中的所有n-grams短序列出现的次数（文档频率）
def countDF(paths, N, top_num):
    # 存放数据集中各个出现过的短序列的次数
    all_feature_dict = {}
    # 存放最高出现次数的top_num个短序列
    topnum_feature_dict = {}
    for path in paths:
        file_list = os.listdir(path)
        for file in file_list:
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
                cur += 1
    sorted_dict = sorted(all_feature_dict.items(), key=lambda x: x[1], reverse=True)
    sorted_dict = sorted_dict[:top_num]
    # 将特征字典返回，形式是{feature1:0, feature2:0, .....}，用于单个文件统计
    for feature in sorted_dict:
        topnum_feature_dict[feature[0]] = 0
    return topnum_feature_dict, all_feature_dict


# 计算TF值，即：用于计算短序列在某个文件中出现的频率
def countTF(file, N):
    tf_dict = {}
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        # 转换成16进制的串表示
        hex_string = str.upper(binascii.b2a_hex(byte).decode('ascii'))
    cur = 0
    while (cur <= len(hex_string)-N):
    # 用大小为N的滑动窗口扫描，截取大小为N的特征
        temp = hex_string[cur:cur + N]
        # 存入字典
        if tf_dict.get(temp):
            tf_dict[temp] += 1
        else:
            tf_dict[temp] = 1
        # 滑动窗口后移一步
        cur += 1
    length = len(tf_dict)
    for key in tf_dict.keys():
        tf_dict[key] /= length
    return tf_dict


# 计算IDF值，即：用于计算出现某个短序列的文件在所有文件中的比值倒数的对数值
# log(D/d)  D为总文件数，小d为出现了某个短序列的文件总数
def countIDF(pattern, sum_of_file, topnum_feature_dict, all_feature_dict):
    # 如果在最终选择的特征库中存在该短序列，那么看一下
    if topnum_feature_dict.get(pattern):
        d = all_feature_dict[pattern]
    else:
        d = 0
    return math.log((sum_of_file/d))



# 用于计算单个文件在特征字典中的所有短序列的TF*IDF的值
# 作为后续分类的特征
def countTFplusIDF(file, sum_of_file, topnum_feature_dict, all_feature_dict, N):
    feature = []
    with open(file, 'rb') as cur_file:
        byte = cur_file.read()
        hex = str.upper(binascii.b2a_hex(byte).decode('ascii'))
    cur = 0
    # 必须先扫描一次该文件，统计该文件中每个短序列出现的频率
    tf_dict = countDF(file, N)
    while cur <= len(hex)-N:
        temp = hex[cur:cur+N]
        if temp in topnum_feature_dict.keys():
            TF = tf_dict.get(temp)
            IDF = countIDF(temp, sum_of_file, topnum_feature_dict, all_feature_dict)
            topnum_feature_dict[temp] = TF*IDF
        else:
            continue
    for val in topnum_feature_dict.values():
        # 一个长度为1Xtop_num的列表
        feature.append(val)
    return feature
