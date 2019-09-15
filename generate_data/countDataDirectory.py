import pefile
from extract import Data_Directory
import os
import csv

mal_path = 'samples/malicious'
beni_path = 'samples/benign'
data_path = 'data_directory_analysis.csv'

def countDataDirectory():
    data = []

    files = os.listdir(mal_path)
    count = 1
    for f in files:
        if count % 100 == 0: print("malicious: {}".format(count))
        count += 1
        try:
            # 第一个位置存储文件名
            features = [f]
            # 接下来存储文件的data_directory的信息
            features.extend(Data_Directory(beni_path + "/" + f))
        except:
            print("ERROR: {}".format(f))
        #加上标签
        features.append(1)
        data.append(features)

    files = os.listdir(beni_path)
    count = 1
    for f in files:
        if count % 100 == 0: print("benign: {}".format(count))
        count += 1
        try:
            features = [f]
            features = Data_Directory(beni_path + "/" + f)
        except:
            print("ERROR: {}".format(f))
        features.append(0)
        data.append(features)
    return data

def save(data):
    if os.path.exists(data_path):
        os.remove(data_path)

    with open(data_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for i in range(len(data)):
            if data[i]:
                writer.writerow(data[i])
    print("save data directory analysis successfully")

if __name__ == '__main__':
    data = countDataDirectory()
    save(data)