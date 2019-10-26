# 《Selecting Features to Classify Malware》
# 选择这7个特征：
# Debug Size、Image Version、Iat RVA、Export Size、Resource Size、Virtual Size2、Number of Sections

# Debug Size：记录了Debug目录表的大小。一般正常PE文件的Debug目录不为空。
# Image Version：标识了PE文件的版本，一般来说正常PE文件该字段都不为0的，而许多恶意软件的该字段为0。
# Iat RVA：输入地址表的相对地址。一般正常文件是4096，而恶意软件的该字段值为0或者一个很大的数。因为许多恶意软件不使用导入函数或者会混淆其输入表。
# Export Size：记录了导出表的大小。通常只有DLL文件或者非可执行文件有导出表，恶意代码的该字段一般为0。
# Resource Size：一般正常文件会有许多资源，而恶意软件为了隐藏身份，几乎没有资源，该字段都是0。
# Virtual Size2:许多恶意代码只有一个Section，该字段一般为0。表示了第二Section（不清楚第二Section是什么）的大小。
# Number Of Sections：标识了PE文件中Section的数量，正常文件以及恶意代码该字段各种值都有，暂不清为什么该特征能较好区分正常文件以及恶意代码
import pefile


def extract(file):
    pe = pefile.PE(file)

    features = []

    features.append(debug_size(pe))
    features.append(image_version(pe))
    features.append(iat_RVA(pe))
    features.append(export_size(pe))
    features.append(resource_size(pe))
    features.append(virtual_size2(pe))
    features.append(number_of_section(pe))

    assert len(features) == 7

    return features


# 1、Debug Size
def debug_size(pe):
    data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    for i in data_dir:
        if i.name == "IMAGE_DIRECTORY_ENTRY_DEBUG":
            return i.Size

    print("No debug_size")
    return 0


# 2、Image Version
def image_version(pe):
    return pe.OPTIONAL_HEADER.MajorImageVersion


# 3、Iat RVA
def iat_RVA(pe):
    data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    for i in data_dir:
        if i.name == "IMAGE_DIRECTORY_ENTRY_IAT":
            return i.VirtualAddress

    print("No iat_rva")
    return 0


# 4、Export Size
def export_size(pe):
    data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    for i in data_dir:
        if i.name == "IMAGE_DIRECTORY_ENTRY_EXPORT":
            return i.Size

    print("No export_size")
    return 0


# 5、Resource Size
def resource_size(pe):
    data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    for i in data_dir:
        if i.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
            return i.Size

    print("No resource_size")
    return 0


# 6、Virtual Size2
def virtual_size2(pe):
    sections = pe.sections

    if len(sections) > 1:
        return sections[1].Misc_VirtualSize
    else:
        return 0


# 7、Number Of Sections
def number_of_section(pe):
    return pe.FILE_HEADER.NumberOfSections
