# 《PE-Miner: Mining Structural Information to Detect Malicious Executables in Realtime》
# DLLs Referred:73个特征，值为0或者1，如果某个PE文件中使用了该DLL，那么相应位置为1。之所以选这个是因为，如果某些文件DLL滥用，可能存在异常行为。
# COFF file header：7个特征。里面包含机器、标志值等字段。恶意代码会有较高或者较少的symbol值。
# Optional header standard fields:9个特征。里面含有连接器版本号、初始化数据大小、未初始化数据大小等字段。正常文件的初始化数据大小字段一般较高。
# Optional header Windows specific fields：22个特征。里面包含操作系统版本、校验和、栈大小、堆大小、文件版本等字段。恶意代码一般没有版本，该字段会为0。
# Data Directory：30个特征。这里面包含了如Import table、Export table等表的偏移地址和大小。正常文件和恶意代码的Import表与Export表有较大的区别。
# Section headers：9X3=27个特征。包含了.text、.data、.rsrc节头部特征（一共15个节，这几个节是最最常用的）。这里面包含了各个节的详细描述。
# Resource directory table&resources：21个特征。分析了资源表和资源。恶意代码的资源一般比较小。

# totally 189 features
import pefile

import extract_parser_features


def extract(file):
    pe = pefile.PE(file)

    features = []
    features.extend(extract_parser_features.Imported_DLL_and_API(pe))
    features.extend(coff(pe))
    features.extend(extract_parser_features.Optional_Header(pe))
    features.extend(extract_parser_features.Data_Directory(pe))
    features.extend(Sections(pe))
    features.extend(extract_parser_features.Resources(pe))

    return features


# COFF
def coff(pe):
    features = []

    temp = pe.FILE_HEADER

    features.append(temp.Machine)  # 16 运行平台    0.8630040084885641
    features.append(temp.NumberOfSections)  # 17 文件的区块数目    0.7618486206083471
    features.append(temp.TimeDateStamp)  # 文件创建日期和时间 不选取
    features.append(temp.PointerToSymbolTable)  # 18 指向符号表（用于调试）
    features.append(temp.NumberOfSymbols)  # 19 符号表中符号个数（用于调试）
    features.append(temp.SizeOfOptionalHeader)  # 20 IMAGE_OPTIONAL_HEADER32结构大小    0.8622966281537373
    features.append(temp.Characteristics)  # 21 文件属性    0.9742985145012969

    return features


def Sections(pe):
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
            elif name == '.data':
                data = list
            elif name == '.rsrc':
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
