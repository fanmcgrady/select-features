import math
import os
import pickle

import pefile

import utils

mal_path = "samples/malicious"
beni_path = "samples/benign"

# step1：提取所有样本的dll
def get_all_dll():

    mal_dll_dict = {}
    mal_api_dict = {}

    beni_dll_dict = {}
    beni_api_dict = {}

    # 提取恶性和良性样本中的DLL和API
    files = os.listdir(mal_path)
    count = 1
    for f in files:
        print("malicious count = {}".format(count))
        count += 1
        pe = pefile.PE(mal_path + "/" + f)
        imports, apis = utils.Imported_DLL_and_API(pe)

        for i in imports:
            value = mal_dll_dict.get(i, 0)
            mal_dll_dict[i] = value + 1

        for i in apis:
            value = mal_api_dict.get(i, 0)
            mal_api_dict[i] = value + 1

    files = os.listdir(beni_path)
    count = 1
    for f in files:
        print("benign count = {}".format(count))
        count += 1
        pe = pefile.PE(beni_path + "/" + f)
        imports, apis = utils.Imported_DLL_and_API(pe)

        for i in imports:
            value = beni_dll_dict.get(i, 0)
            beni_dll_dict[i] = value + 1

        for i in apis:
            value = beni_api_dict.get(i, 0)
            beni_api_dict[i] = value + 1

    # print(len(mal_dll_dict))
    # print(len(mal_api_dict))
    # print(len(beni_dll_dict))
    # print(len(beni_api_dict))
    #
    # 保存
    with open("result/dll_api/all-mal-dll.pkl", 'wb') as f:
        pickle.dump(mal_dll_dict, f, pickle.HIGHEST_PROTOCOL)

    with open("result/dll_api/all-mal-api.pkl", 'wb') as f:
        pickle.dump(mal_api_dict, f, pickle.HIGHEST_PROTOCOL)

    with open("result/dll_api/all-beg-dll.pkl", 'wb') as f:
        pickle.dump(beni_dll_dict, f, pickle.HIGHEST_PROTOCOL)

    with open("result/dll_api/all-beg-api.pkl", 'wb') as f:
        pickle.dump(beni_api_dict, f, pickle.HIGHEST_PROTOCOL)


# step2：计算所有恶意样本的信息增益
def get_mal_info():
    # 读取
    with open("result/dll_api/all-mal-dll.pkl", 'rb') as f:
        mal_dll_dict = pickle.load(f)

    with open("result/dll_api/all-mal-api.pkl", 'rb') as f:
        mal_api_dict = pickle.load(f)

    with open("result/dll_api/all-beg-dll.pkl", 'rb') as f:
        beni_dll_dict = pickle.load(f)

    with open("result/dll_api/all-beg-api.pkl", 'rb') as f:
        beni_api_dict = pickle.load(f)

    # 信息熵计算
    def E(count, sum):
        if count == 0:
            return 0
        else:
            return -(count / sum) * math.log((count / sum), 2)

    files = os.listdir(mal_path)
    mal_total = len(files)
    files = os.listdir(beni_path)
    beni_total = len(files)

    sum = mal_total + beni_total
    E_total = E(mal_total, sum) + E(beni_total, sum)

    dll_dict = {}
    api_dict = {}

    # 整合dict和api
    def info(m1, b1):
        m0 = mal_total - m1
        b0 = beni_total - b1
        sum1 = m1 + b1
        sum0 = m0 + b0

        # print("m1 = {},b1 = {}".format(m1, b1))
        E_0 = E(m0, sum0) + E(b0, sum0)
        E_1 = E(m1, sum1) + E(b1, sum1)

        result = E_total - (sum0 / sum) * E_0 - (sum1 / sum) * E_1
        # print(result)
        return result

    for key in mal_dll_dict.keys():
        mal = mal_dll_dict[key]
        beni = beni_dll_dict.get(key, 0)
        value = info(mal, beni)
        dll_dict[key] = value

    for key in beni_dll_dict.keys():
        if dll_dict.get(key, None):
            continue
        else:
            dll_dict[key] = info(0, beni_dll_dict[key])

    # 恶意样本中全部dll的信息增益字典：
    # key：dll名字
    # value：信息增益
    with open("result/dll_api/mal-info-dll.pkl", 'wb') as f:
        pickle.dump(dll_dict, f, pickle.HIGHEST_PROTOCOL)

    for key in mal_api_dict.keys():
        mal = mal_api_dict[key]
        beni = beni_api_dict.get(key, 0)
        value = info(mal, beni)
        api_dict[key] = value

    for key in beni_api_dict.keys():
        if api_dict.get(key, None):
            continue
        else:
            api_dict[key] = info(0, beni_api_dict[key])

    with open("result/dll_api/mal-info-api.pkl", 'wb') as f:
        pickle.dump(api_dict, f, pickle.HIGHEST_PROTOCOL)

# step3：选出恶意样本top30信息增益
def get_top30_mal_info():
    # 读取
    with open("result/dll_api/mal-info-dll.pkl", 'rb') as f:
        dll_dict = pickle.load(f)
    with open("result/dll_api/mal-info-api.pkl", 'rb') as f:
        api_dict = pickle.load(f)

    sorted_dll_dict = {}
    sorted_api_dict = {}

    # 选取30个
    sorted_dll = sorted(dll_dict.items(), key=lambda x: x[1], reverse=True)
    count = 0
    for i in sorted_dll:
        sorted_dll_dict[i[0]] = i[1]
        count += 1
        if count == 30: break
    count = 0
    sorted_api = sorted(api_dict.items(), key=lambda x: x[1], reverse=True)
    for i in sorted_api:
        sorted_api_dict[i[0]] = i[1]
        count += 1
        if count == 30: break

    # 保存排序好的dll信息增益字典，取前30个
    with open("result/dll_api/top30-mal-info-dll.pkl", 'wb') as f:
        pickle.dump(sorted_dll_dict, f, pickle.HIGHEST_PROTOCOL)

    with open("result/dll_api/top30-mal-info-api.pkl", 'wb') as f:
        pickle.dump(sorted_api_dict, f, pickle.HIGHEST_PROTOCOL)


# step4：求恶意样本dll与选定的dll的交集top30
def get_intersection_top30():
    list = ['ADVAP132.DLL', 'AWFAXP32.DLL', 'AWFXAB32.DLL', 'AWPWD32.DLL', 'AWRESX32.DLL', 'AWUTIL32.DLL', 'BHNETB.DLL',
            'BHSUPP.DLL', 'CCAPI.DLL', 'CCEI.DLL', 'CCPSH.DLL', 'CCTN20.DLL', 'CMC.DLL', 'COMCTL32.DLL', 'COMDLG32.DLL',
            'CRTDLL.DLL', 'DCIMAN.DLL', 'DCIMAN32.DLL', 'DSKMAINT.DLL', 'GDI32.DLL', 'GROUPPOL.DLL', 'HYPERTERM.DLL',
            'KERNL32.DLL', 'LZ32.DLL', 'MAPI.DLL', 'MAPI32.DLL', 'MFC30.DLL', 'MPR.DLL', 'MSPST32.DLL', 'MSFS32.DLL',
            'MSNDUI.DLL', 'MSNET32.DLL', 'MSSHRUI.DLL', 'MSVIEWUT.DLL', 'NAL.DLL', 'NDIS30.DLL', 'NETAPI.DLL',
            'NETAPI32.DLL', 'NETBIOS.DLL', 'NETDI.DLL', 'NETSETUP.DLL', 'NWAB32.DLL', 'NWNET32.DLL', 'NWNP32.DLL',
            'OLEDLG.DLL', 'POWERCFG.DLL', 'RASPI.DLL', 'RASAPI16.DLL', 'RASAPI32.DLL', 'RPCRT4.DLL', 'RPCLTC1.DLL',
            'RPCTLC3.DLL', 'RPCTLC5.DLL', 'RPCTLC6.DLL', 'RPCTLS3.DLL', 'RPCTLS5.DLL', 'RPCTLS6.DLL', 'RPCNS4.DLL',
            'RSRC32.DLL', 'SAPNSP.DLL', 'SECUR32.DLL', 'SHELL32.DLL', 'SLENH.DLL', 'SHLWAPI.DLL', 'UMDM32.DLL',
            'USER32.DLL', 'VERSION.DLL', 'WININET.DLL', 'WINMM.DLL', 'WINREG.DLL', 'WINSOCK.DLL', 'WS2_32.DLL',
            'WSOCK32.DLL']

    with open("result/dll_api/mal-info-dll.pkl", 'rb') as f:
        dll_dict = pickle.load(f)

    dict = {}  # 取现有dict和list的交集

    # 1、另外的dll与全部恶意样本dll交集放入dict
    # 2、对dict排序
    for i in list:
        # print(i)
        if dll_dict.get(i, 0):
            dict[i] = dll_dict.get(i, 0)

    sorted_dll_dict = {}

    sorted_dll = sorted(dict.items(), key=lambda x: x[1], reverse=True)
    count = 0
    for i in sorted_dll:
        sorted_dll_dict[i[0]] = i[1]
        count += 1
        if count == 30: break

    with open("result/dll_api/intersection-top30.pkl", 'wb') as f:  # 这个dict是和list取交集之后的
        pickle.dump(sorted_dll_dict, f, pickle.HIGHEST_PROTOCOL)

if __name__ == '__main__':
    # step1
    get_all_dll()
    # step2
    get_mal_info()
    # step3
    get_top30_mal_info()
    # step4
    get_intersection_top30()
