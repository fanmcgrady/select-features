import csv
import os
from . import extract

mal_path = "samples/malicious"
beni_path = "samples/benign"
data_path = "samples_112.csv"

test_path = "samples/Virus.Win"

def generate_data():
    global features
    data = []

    files = os.listdir(mal_path)
    count = 1
    for f in files:
        if count % 100 == 0: print("malicious: {}".format(count))
        count += 1
        try:
            features = extract.extract(mal_path + "/" + f)
        except:
            print("ERROR: {}".format(f))
        features.append(1)
        if len(features) != 113: print("{}: {}".format(len(features), f))
        data.append(features)

    files = os.listdir(beni_path)
    count = 1
    for f in files:
        if count % 100 == 0: print("benign: {}".format(count))
        count += 1
        try:
            features = extract.extract(beni_path + "/" + f)
        except:
            print("ERROR: {}".format(f))
        features.append(0)
        if len(features) != 113: print("{}: {}".format(len(features), f))
        data.append(features)
    return data

# files = os.listdir(test_path)
# print(len(files))
# for f in files:
#     with open(test_path + "/" + f, "rb") as infile:
#         try:
#             features = extract(infile)
#         except:
#             print("remove {}".format(f))
#             # os.remove(test_path + "/" + f)
#         else:
#             features.append(1)
#             # print("name: {}, length = {}".format(f, len(features)))
#             data.append(features)
#
# return data


def save(data):
    if os.path.exists(data_path):
        os.remove(data_path)

    with open(data_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for i in range(len(data)):
            if data[i]:
                writer.writerow(data[i])
    print("save data successfully")


def load():
    data = []
    with open(data_path) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            for i in range(len(row)):
                if row[i] == 'True':
                    row[i] = True
                elif row[i] == 'False':
                    row[i] = False
                else:
                    row[i] = int(row[i])
            data.append(row)


# os.remove("samples/benign/.DS_Store")
# os.remove("samples/malicious/Virus.Win32.VB.jt")
# os.remove("samples/malicious/Virus.Win9x.Anxiety.1586")
# os.remove("samples/malicious/Virus.Win9x.Anxiety.1397")
# os.remove("samples/malicious/Virus.Win32.VB.aq")
# os.remove("samples/malicious/Virus.Win9x.Anxiety.1823.b")
data = generate_data()
save(data)
# data = load()

# path = "samples/test"
# files = os.listdir(path)
# for f in files:
#     with open(path + "/" + f, "rb") as infile:
#         bytez = infile.read()
#         print(feature_extractor.extract(bytez))
