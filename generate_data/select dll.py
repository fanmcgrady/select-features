import pefile
import os
import extract
import pickle
import math

mal_path = "samples/malicious"
beni_path = "samples/benign"

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
    imports, apis = extract.Imported_DLL_and_API(pe)

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
    imports, apis = extract.Imported_DLL_and_API(pe)

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
with open("malicious dll dict.pkl", 'wb') as f:
    pickle.dump(mal_dll_dict, f, pickle.HIGHEST_PROTOCOL)

with open("malicious api dict.pkl", 'wb') as f:
    pickle.dump(mal_api_dict, f, pickle.HIGHEST_PROTOCOL)

with open("benign dll dict.pkl", 'wb') as f:
    pickle.dump(beni_dll_dict, f, pickle.HIGHEST_PROTOCOL)

with open("benign api dict.pkl", 'wb') as f:
    pickle.dump(beni_api_dict, f, pickle.HIGHEST_PROTOCOL)

# 读取
with open("malicious dll dict.pkl", 'rb') as f:
    mal_dll_dict = pickle.load(f)

with open("malicious api dict.pkl", 'rb') as f:
    mal_api_dict = pickle.load(f)

with open("benign dll dict.pkl", 'rb') as f:
    beni_dll_dict = pickle.load(f)

with open("benign api dict.pkl", 'rb') as f:
    beni_api_dict = pickle.load(f)


# 信息熵计算
def E(count, sum):
    if count == 0:
        return 0
    else:
        return -(count / sum) * math.log((count / sum), 2)


mal_total = 3010
beni_total = 3140
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

# 保存整合之后的
with open("ddl dict.pkl", 'wb') as f:
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

with open("api dict.pkl", 'wb') as f:
    pickle.dump(api_dict, f, pickle.HIGHEST_PROTOCOL)
print(api_dict)

# 读取
with open("dll dict.pkl", 'rb') as f:
    dll_dict = pickle.load(f)
with open("api dict.pkl", 'rb') as f:
    api_dict = pickle.load(f)

# print(len(dll_dict))
# print(len(api_dict))
sorted_dll_dict = {}
sorted_api_dict = {}

# 选取20个
sorted_dll = sorted(dll_dict.items(), key=lambda x: x[1], reverse=True)
count = 0
for i in sorted_dll:
    sorted_dll_dict[i[0]] = i[1]
    count += 1
    if count == 20: break
count = 0
sorted_api = sorted(api_dict.items(), key=lambda x: x[1], reverse=True)
for i in sorted_api:
    sorted_api_dict[i[0]] = i[1]
    count += 1
    if count == 20: break

# print(sorted_dll_dict)
# print(sorted_api_dict)
#
os.remove("ddl dict.pkl")
os.remove("api dict.pkl")

# 保存
with open("selected dll dict.pkl", 'wb') as f:
    pickle.dump(sorted_dll_dict, f, pickle.HIGHEST_PROTOCOL)

with open("selected api dict.pkl", 'wb') as f:
    pickle.dump(sorted_api_dict, f, pickle.HIGHEST_PROTOCOL)

# 读取
with open("malicious dll dict.pkl", 'rb') as f:
    dll_dict = pickle.load(f)

with open("api dict.pkl", 'rb') as f:
    api_dict = pickle.load(f)

# print(len(dll_dict))
# # print(len(api_dict))
# print(dll_dict['SECUR32.DLL'])
# print(api_dict)
# print(sorted(zip(mal_dll_dict.values(), mal_dll_dict.keys())))
# print(sorted(zip(mal_api_dict.values(), mal_api_dict.keys())))


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

with open("dll dict.pkl", 'rb') as f:
    dll_dict = pickle.load(f)

dict = {} #取现有dict和list的交集
count = 0

for i in list:
    # print(i)
    if dll_dict.get(i, 0):
        count += 1
        dict[i] = dll_dict.get(i, 0)

sorted_dll_dict = {}

sorted_dll = sorted(dict.items(), key=lambda x: x[1], reverse=True)
count = 0
for i in sorted_dll:
    sorted_dll_dict[i[0]] = i[1]
    count += 1
    if count == 20: break

os.remove("ddl dict.pkl")
os.remove("api dict.pkl")

with open("selected dll dict(new).pkl", 'wb') as f:   #这个dict是和list取交集之后的
    pickle.dump(sorted_dll_dict, f, pickle.HIGHEST_PROTOCOL)

with open("selected dll dict(new).pkl", 'rb') as f:
    dll_dict = pickle.load(f)

# num = 142
# for key in dll_dict.keys():
#     print("{}:{}".format(num, key))
#     num += 1

# with open("selected dll dict(new).pkl", 'rb') as f:
#     dll_dict = pickle.load(f)
#
# num = 142
# for key in dll_dict.keys():
#     print("{}:{}".format(num, key))
#     num += 1
