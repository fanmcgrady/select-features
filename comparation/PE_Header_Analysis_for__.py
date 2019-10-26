# 《PE Header Analysis for Malware Detection》
import binascii

import pefile

import extract_parser_features


def extract(file):
    pe = pefile.PE(file)
    features = []

    doc = pe.DOS_HEADER

    features.append(doc.e_magic)
    features.append(doc.e_cblp)
    features.append(doc.e_cp)
    features.append(doc.e_crlc)
    features.append(doc.e_cparhdr)
    features.append(doc.e_minalloc)
    features.append(doc.e_maxalloc)
    features.append(doc.e_ss)
    features.append(doc.e_sp)
    features.append(doc.e_csum)
    features.append(doc.e_ip)
    features.append(doc.e_cs)
    features.append(doc.e_lfarlc)
    features.append(doc.e_res)
    features.append(doc.e_oemid)
    features.append(doc.e_oeminfo)
    features.append(doc.e_lfanew)
    features.append(doc.e_ovno)

    hex_string = str.upper(binascii.b2a_hex(doc.e_res2).decode('ascii'))
    cur = 0
    # 统计出现过的短字符次数，重复计数，如AE30的短序列之前出现过，这次也要计数
    while (cur <= len(hex_string) - 2):
        # 用大小为N的滑动窗口扫描，截取大小为N的特征
        temp = hex_string[cur:cur + 2]
        features.append(temp)
        cur += 2

    features.append(pe.NT_HEADERS.Signature)

    file_header = pe.FILE_HEADER
    features.append(file_header.Machine)  # 16 运行平台
    features.append(file_header.NumberOfSections)  # 17 文件的区块数目
    features.append(file_header.TimeDateStamp)  # 文件创建日期和时间 不选取
    features.append(file_header.PointerToSymbolTable)  # 18 指向符号表（用于调试）
    features.append(file_header.NumberOfSymbols)  # 19 符号表中符号个数（用于调试）
    features.append(file_header.SizeOfOptionalHeader)  # 20 IMAGE_OPTIONAL_HEADER32结构大小
    features.append(file_header.Characteristics)  # 21 文件属性

    features.extend(extract_parser_features.Optional_Header(pe))

    sections = pe.sections
    list = []
    for f in sections:
        name = str(f.Name, encoding="utf8").strip('\x00')
        if name == '.text':
            list.append(f.Misc)  # 与Misc_VirtualSize相同，不选取
            list.append(f.Misc_PhysicalAddress)  # 与Misc_VirtualSize相同，不选取
            list.append(f.Misc_VirtualSize)  # 区块尺寸
            list.append(f.VirtualAddress)  # 区块的RVA地址
            list.append(f.SizeOfRawData)  # 在文件中对齐后的尺寸
            list.append(f.PointerToRawData)  # 在文件中偏移
            list.append(f.PointerToRelocations)  # 在OBJ文件中使用，重定位的偏移
            list.append(f.PointerToLinenumbers)  # 行号表的偏移（供调试使用）
            list.append(f.NumberOfRelocations)  # 在OBJ文件中使用，重定位项数目
            list.append(f.NumberOfLinenumbers)  # 行号表中行号的数目
            list.append(f.Characteristics)  # 区块属性如可读，可写，可执行等
            list.append(1)
            break

    if len(list) == 12:
        features.extend(list)
    else:
        list2 = []
        for i in range(12):
            list2.append(0)
        features.extend(list2)

    print(len(features))
    assert len(features) == 87

    return features
