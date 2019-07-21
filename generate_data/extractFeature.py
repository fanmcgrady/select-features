import os

import lief
import pefile


def extract(f):
    binary = lief.PE.parse(f.read())

    features = Dos_Header(binary)
    features.extend(Header(binary))
    features.extend(Optional_Header(binary))
    features.extend(Data_Directory(binary))
    features = features.extend(Import_DLL(binary))
    features = features.extend(Import_API(binary))
    features.extend(Sections(binary))
    return features


# 17
def Dos_Header(binary):
    list = []
    dos_header = binary.dos_header

    e_magic = dos_header.magic
    list.append(e_magic)

    e_cblp = dos_header.used_bytes_in_the_last_page
    list.append(e_cblp)

    e_cp = dos_header.file_size_in_pages
    list.append(e_cp)

    e_crlc = dos_header.numberof_relocation
    list.append(e_crlc)

    e_cparhdr = dos_header.header_size_in_paragraphs
    list.append(e_cparhdr)

    e_minalloc = dos_header.minimum_extra_paragraphs
    list.append(e_minalloc)

    e_maxalloc = dos_header.maximum_extra_paragraphs
    list.append(e_maxalloc)

    e_ss = dos_header.initial_relative_ss
    list.append(e_ss)

    e_sp = dos_header.initial_sp
    list.append(e_sp)

    e_csum = dos_header.checksum
    list.append(e_csum)

    e_ip = dos_header.initial_ip
    list.append(e_ip)

    e_cs = dos_header.initial_relative_cs
    list.append(e_cs)

    e_lfarlc = dos_header.addressof_relocation_table
    list.append(e_lfarlc)

    e_ovno = dos_header.overlay_number
    list.append(e_ovno)

    e_oemid = dos_header.oem_id
    list.append(e_oemid)

    e_oeminfo = dos_header.oem_info
    list.append(e_oeminfo)

    e_lfanew = dos_header.addressof_new_exeheader  # important
    list.append(e_lfanew)

    return list


# 7
def Header(binary):
    list = []
    header = binary.header

    machine = header.machine
    list.append(machine)

    number_of_sections = header.numberof_sections
    list.append(number_of_sections)

    time_date_stamp = header.time_date_stamps
    list.append(time_date_stamp)

    pointer_to_symbol_table = header.pointerto_symbol_table
    list.append(pointer_to_symbol_table)

    number_of_symbols = header.numberof_symbols
    list.append(number_of_symbols)

    size_of_optional_header = header.sizeof_optional_header
    list.append(size_of_optional_header)

    characteristics = header.characteristics
    list.append(characteristics)

    return list


# 30
def Optional_Header(binary):
    list = []
    optional_header = binary.optional_header

    magic = optional_header.magic
    list.append(magic)

    major_linker_version = optional_header.major_linker_version
    list.append(major_linker_version)

    minor_linker_version = optional_header.minor_linker_version
    list.append(minor_linker_version)

    size_of_code = optional_header.sizeof_code
    list.append(size_of_code)

    size_of_initialized_data = optional_header.sizeof_initialized_data
    list.append(size_of_initialized_data)

    size_of_uninitialized_data = optional_header.sizeof_uninitialized_data
    list.append(size_of_uninitialized_data)

    address_of_entry_point = optional_header.addressof_entrypoint
    list.append(address_of_entry_point)

    base_of_code = optional_header.baseof_code
    list.append(base_of_code)

    bade_of_data = optional_header.baseof_data
    list.append(bade_of_data)

    image_base = optional_header.imagebase
    list.append(image_base)

    section_alignment = optional_header.section_alignment
    list.append(section_alignment)

    file_alignment = optional_header.file_alignment
    list.append(file_alignment)

    major_operating_system_version = optional_header.major_operating_system_version
    list.append(major_operating_system_version)

    minor_operating_system_version = optional_header.minor_operating_system_version
    list.append(minor_operating_system_version)

    major_image_version = optional_header.major_image_version
    list.append(major_image_version)

    minor_image_version = optional_header.minor_image_version
    list.append(minor_image_version)

    major_subsystem_version = optional_header.major_subsystem_version
    list.append(major_subsystem_version)

    minor_subsystem_version = optional_header.minor_subsystem_version
    list.append(minor_subsystem_version)

    win32_version_value = optional_header.win32_version_value
    list.append(win32_version_value)

    size_of_image = optional_header.sizeof_image
    list.append(size_of_image)

    size_of_headers = optional_header.sizeof_headers
    list.append(size_of_headers)

    checksum = optional_header.checksum
    list.append(checksum)

    subsystem = optional_header.subsystem
    list.append(subsystem)

    Dll_Characteristics = optional_header.dll_characteristics
    list.append(Dll_Characteristics)

    size_of_stack_reserve = optional_header.sizeof_stack_reserve
    list.append(size_of_stack_reserve)

    size_of_stack_commit = optional_header.sizeof_stack_commit
    list.append(size_of_stack_commit)

    size_of_heap_reserve = optional_header.sizeof_heap_reserve
    list.append(size_of_heap_reserve)

    size_of_heap_commit = optional_header.sizeof_heap_commit
    list.append(size_of_heap_commit)

    loader_flags = optional_header.loader_flags
    list.append(loader_flags)

    number_of_RVA_and_size = optional_header.numberof_rva_and_size
    list.append(number_of_RVA_and_size)

    return list


# 30
def Data_Directory(binary):
    data_directory = binary.data_directories
    rva = []
    size = []
    for i in data_directory:
        rva.append(i.rva)
        size.append(i.size)
    if len(rva) < 15:
        for i in range(15 - len(rva)):
            rva.append(0)
            size.append(0)
    rva.extend(size)
    return rva


def Import_DLL(binary):
    imports = []
    try:
        temp = binary.imports
    except:
        return []

    for i in temp:
        imports.append(i.name)
    imports = [x.upper() for x in imports]
    return imports


def Import_API(binary):
    api = []
    try:
        api = binary.imported_functions
    except:
        return []
    api = [x.upper() for x in api]
    return api


# 27
def Sections(binary):
    sections = binary.sections
    text = []
    data = []
    rsrc = []
    for i in sections:
        if i.name == '.text' or i.name == '.data' or i.name == '.rsrc':
            list = []

            virtual_size = i.virtual_size
            list.append(virtual_size)

            virtual_address = i.virtual_address
            list.append(virtual_address)

            sizeof_raw_data = i.sizeof_raw_data
            list.append(sizeof_raw_data)

            pointerto_raw_data = i.pointerto_raw_data
            list.append(pointerto_raw_data)

            pointerto_relocation = i.pointerto_relocation
            list.append(pointerto_relocation)

            pointerto_line_numbers = i.pointerto_line_numbers
            list.append(pointerto_line_numbers)

            numberof_relocations = i.numberof_relocations
            list.append(numberof_relocations)

            numberof_line_numbers = i.numberof_line_numbers
            list.append(numberof_line_numbers)

            characteristics = i.characteristics
            list.append(characteristics)

            if i.name == '.text':
                text = list
            if i.name == '.data':
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


# os.remove("samples/malicious/Virus.Win32.Stepar.j")
# path = "samples/malicious/Virus.Win9x.Bonk.1232"
# with open(path, "rb") as infile:
#     binary = lief.PE.parse(infile.read())
# # print(binary)
# pe = pefile.PE(path)
# print(pe)
# for i in pe.DIRECTORY_ENTRY_RESOURCE.entries:
#     print(i.id)
# temp = binary.sections
# for i in temp:
#     print(i.name)
#     print(i.virtual_address)
#     print(i.virtual_size)
# print(binary)

# files = os.listdir("samples/benign")
# print(len(files))
