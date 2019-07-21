import os
import pickle

import pefile
import random

# 解析pe文件，提取相应指标

with open("selected dll dict(new).pkl", 'rb') as f:
    dll_dict = pickle.load(f)

with open("selected api dict.pkl", 'rb') as f:
    api_dict = pickle.load(f)


def extract(file):
    features = []

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

    return features


def File_Header(pe):
    features = []

    temp = pe.FILE_HEADER

    features.append(temp.Machine)  # 17
    features.append(temp.NumberOfSections)  # 18
    features.append(temp.TimeDateStamp)  # 19
    features.append(temp.PointerToSymbolTable)  # 20
    features.append(temp.NumberOfSymbols)  # 21
    features.append(temp.SizeOfOptionalHeader)  # 22
    features.append(temp.Characteristics)  # 23

    if temp.NumberOfSections == len(pe.sections):  # 24
        features.append(1)
    else:
        features.append(0)
    return features


def Optional_Header(pe):
    features = []
    temp = pe.OPTIONAL_HEADER

    features.append(temp.Magic)  # 25
    features.append(temp.MajorLinkerVersion)  # 26
    features.append(temp.MinorLinkerVersion)  # 27
    features.append(temp.SizeOfCode)  # 28
    features.append(temp.SizeOfInitializedData)  # 29
    features.append(temp.SizeOfUninitializedData)  # 30
    features.append(temp.AddressOfEntryPoint)  # 31
    features.append(temp.BaseOfCode)  # 32
    features.append(temp.ImageBase)  # 33
    features.append(temp.SectionAlignment)  # 34
    features.append(temp.FileAlignment)  # 35
    features.append(temp.MajorOperatingSystemVersion)  # 36
    features.append(temp.MinorOperatingSystemVersion)  # 37
    features.append(temp.MajorImageVersion)  # 38
    features.append(temp.MinorImageVersion)  # 39
    features.append(temp.MajorSubsystemVersion)  # 40
    features.append(temp.MinorSubsystemVersion)  # 41
    features.append(temp.Reserved1)  # 42
    features.append(temp.SizeOfImage)  # 43
    features.append(temp.SizeOfHeaders)  # 44
    features.append(temp.CheckSum)  # 45
    features.append(temp.Subsystem)  # 46
    features.append(temp.DllCharacteristics)  # 47
    features.append(temp.SizeOfStackReserve)  # 48
    features.append(temp.SizeOfStackCommit)  # 49
    features.append(temp.SizeOfHeapReserve)  # 50
    features.append(temp.SizeOfHeapCommit)  # 51
    features.append(temp.LoaderFlags)  # 52
    features.append(temp.NumberOfRvaAndSizes)  # 53
    features.append(temp.DllCharacteristics)  # 54

    return features


def Dos_Header(pe):
    features = []

    temp = pe.DOS_HEADER

    features.append(temp.e_magic)  # 1
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
    # features.append(temp.e_res)
    features.append(temp.e_oemid)  # 14
    features.append(temp.e_oeminfo)  # 15
    # features.append(temp.e_res2)
    features.append(temp.e_lfanew)  # 16

    # print(len(features))
    return features


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

    for key in api_dict.keys():
        exist = False
        for i in apis:
            if i == key:
                api.append(1)
                exist = True
                break
        if not exist:
            api.append(0)

    result = dll
    # result.extend(api)
    result.append(len(dlls))
    result.append(len(apis))

    # print("dll = {}, api = {}".format(len(dll),len(api)))
    # print(len(result))
    return result


def Sections(pe):
    # 87 - 119
    text = []
    data = []
    rsrc = []
    sections = pe.sections

    for f in sections:
        # print(f.Name)
        name = str(f.Name, encoding="utf8").strip('\x00')
        if name == '.text' or name == '.data' or name == '.rsrc':
            list = []
            list.append(f.Misc)
            list.append(f.Misc_PhysicalAddress)
            list.append(f.Misc_VirtualSize)
            list.append(f.VirtualAddress)
            list.append(f.SizeOfRawData)
            list.append(f.PointerToRawData)
            list.append(f.PointerToRelocations)
            list.append(f.PointerToLinenumbers)
            list.append(f.NumberOfRelocations)
            list.append(f.NumberOfLinenumbers)
            list.append(f.Characteristics)

            if name == '.text':
                text = list
            elif name == '.dara':
                data = list
            else:
                rsrc = list

    if len(text) == 0:
        for i in range(11):
            text.append(0)
    if len(data) == 0:
        for i in range(11):
            data.append(0)

    if len(rsrc) == 0:
        for i in range(11):
            rsrc.append(0)

    text.extend(data)
    text.extend(rsrc)

    return text


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

file = "samples/malicious/Virus.Win32.Priest.a"
temp = extract(file)
# print(len(temp))

# count = 1
# files = os.listdir("samples/benign")
# for f in files:
#     temp = random.random()
#     if temp > 0.8:
#         print(count)
#         count+=1
#         os.remove("samples/benign/" + f)
