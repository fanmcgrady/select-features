import pefile


# with open("intersection-top20.pkl", 'rb') as f:
#     dll_dict = pickle.load(f)


# with open("selected api dict.pkl", 'rb') as f:
#     api_dict = pickle.load(f)


# 解析pe文件，提取相应指标
def extract(file):
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
    # features.extend(Resources(pe))
    # print(len(features))
    # features.extend(Imported_DLL_and_API(pe))
    # print(len(features))

    return features


# DOS 头部，15个指标，选取该部分除了保留字之外的所有属性
def Dos_Header(pe):
    features = []

    temp = pe.DOS_HEADER
    # features.append(temp.e_magic)  # 1 固定值'MZ'(是为了纪念MS-DOS的最初创建者Mark Zbikowski)，不选取
    features.append(temp.e_cblp)  # 1
    features.append(temp.e_cp)  # 2
    features.append(temp.e_crlc)  # 3
    features.append(temp.e_cparhdr)  # 4
    features.append(temp.e_minalloc)  # 5
    features.append(temp.e_maxalloc)  # 6
    features.append(temp.e_ss)  # 7
    features.append(temp.e_sp)  # 8
    features.append(temp.e_csum)  # 9
    features.append(temp.e_ip)  # 10
    features.append(temp.e_cs)  # 11
    features.append(temp.e_lfarlc)  # 12
    # features.append(temp.e_res)  # 保留字
    features.append(temp.e_oemid)  # 13
    features.append(temp.e_oeminfo)  # 14
    # features.append(temp.e_res2)  # 保留字
    features.append(temp.e_lfanew)  # 15    0.7540674369252535

    return features


# File Header，7个指标
def File_Header(pe):
    features = []

    temp = pe.FILE_HEADER

    features.append(temp.Machine)  # 16 运行平台    0.8630040084885641
    features.append(temp.NumberOfSections)  # 17 文件的区块数目    0.7618486206083471
    # features.append(temp.TimeDateStamp)  # 文件创建日期和时间 不选取
    features.append(temp.PointerToSymbolTable)  # 18 指向符号表（用于调试）
    features.append(temp.NumberOfSymbols)  # 19 符号表中符号个数（用于调试）
    features.append(temp.SizeOfOptionalHeader)  # 20 IMAGE_OPTIONAL_HEADER32结构大小    0.8622966281537373
    features.append(temp.Characteristics)  # 21 文件属性    0.9742985145012969

    # 该部分提供的节数是否等于真实节数，等于则值为 1，否则为0
    if temp.NumberOfSections == len(pe.sections):  # 22
        features.append(1)
    else:
        features.append(0)
    return features


# Optional Header，29个指标，选择该部分的所有属性
def Optional_Header(pe):
    features = []
    temp = pe.OPTIONAL_HEADER

    features.append(temp.Magic)  # 23 标志字, ROM 映像（0107h）,普通可执行文件（010Bh） 0.8630040084885641
    features.append(temp.MajorLinkerVersion)  # 24 链接程序的主版本号    0.9460033011082292
    features.append(temp.MinorLinkerVersion)  # 25 链接程序的次版本号    0.7568969582645603
    features.append(temp.SizeOfCode)  # 26 所有含代码的节的总大小  0.7156331053996698
    features.append(temp.SizeOfInitializedData)  # 27 所有含已初始化数据的节的总大小   0.7092666823862297
    features.append(temp.SizeOfUninitializedData)  # 28 所有含未初始化数据的节的大小
    features.append(temp.AddressOfEntryPoint)  # 29 程序执行入口RVA   0.8024050931384108
    features.append(temp.BaseOfCode)  # 30 代码的区块的起始RVA
    # features.append(temp.BaseOfData)  # 数据的区块的起始RVA 源码显示64位PE文件无该字段，所以不选取
    features.append(temp.ImageBase)  # 31 程序的首选装载地址 0.850742749351568
    features.append(temp.SectionAlignment)  # 32 内存中的区块的对齐大小
    features.append(temp.FileAlignment)  # 33 文件中的区块的对齐大小
    features.append(temp.MajorOperatingSystemVersion)  # 34 要求操作系统最低版本号的主版本号    0.9438811601037491
    features.append(temp.MinorOperatingSystemVersion)  # 35 要求操作系统最低版本号的副版本号    0.894600330110823
    features.append(temp.MajorImageVersion)  # 36 可运行于操作系统的主版本号 0.87314312662108
    features.append(temp.MinorImageVersion)  # 37 可运行于操作系统的次版本号 0.8521575100212214
    features.append(temp.MajorSubsystemVersion)  # 38 要求最低子系统版本的主版本号    0.9587361471351097
    features.append(temp.MinorSubsystemVersion)  # 39 要求最低子系统版本的次版本号    0.8818674840839424
    features.append(temp.Reserved1)  # 40 莫须有字段，不被病毒利用的话一般为0
    features.append(temp.SizeOfImage)  # 41 映像装入内存后的总尺寸
    features.append(temp.SizeOfHeaders)  # 42 所有头 + 区块表的尺寸大小
    features.append(temp.CheckSum)  # 43 映像的校检和 0.7762320207498231
    features.append(temp.Subsystem)  # 44 可执行文件期望的子系统   0.7734024994105164
    features.append(temp.DllCharacteristics)  # 45 DllMain()函数何时被调用，默认为 0   0.9665173308182032
    features.append(temp.SizeOfStackReserve)  # 46 初始化时的栈大小 0.7708087715161519
    features.append(temp.SizeOfStackCommit)  # 47 初始化时实际提交的栈大小
    features.append(temp.SizeOfHeapReserve)  # 48 初始化时保留的堆大小
    features.append(temp.SizeOfHeapCommit)  # 49 初始化时实际提交的堆大小
    features.append(temp.LoaderFlags)  # 50 与调试有关，默认为0
    features.append(temp.NumberOfRvaAndSizes)  # 51 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16

    return features


# 数据目录表，32个指标，保存 16 个目录表的虚拟地址和大小，
# 若某个目录表不存在，则属性全部置为 0
def Data_Directory(pe):
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
    return features


# .text 节/.data 节/.rsrc 节，27 个指标，选择该部分的所有属性
# .idata/.rdata/.reloc
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
