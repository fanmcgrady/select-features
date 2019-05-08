import csv

import matplotlib.pyplot as plt

# x = [5, 6, 7, 8, 9, 10]
# # Decision Tree
# y_final = [93.01, 86.88, 97.55, 98.12, 96.48, 95.1]
# y_best_eval = [96.18, 97.56, 98.70, 98.64, 97.51, 99.13]
#
#
# y_best_train = [99.96, 97.52, 99.98, 99.98, 99.98, 99.98]
# y_mean = [93.01, 96.90, 99.59, 97.74, 99.89, 99.70]
#
# #KNN
# # y_final = [91.36, 97.64, 94.77, 94.93, 88.07, 98.82]
# # y_best_eval = [93.37, 97.64, 96.86, 98.15, 97.58, 99.12]
# # y_final = [91.36,]
# # y_best_train = [99.84,99.16]
# # y_best_eval = [99.78,]
# # y_mean = [93.37,77.62]
#
# plt.plot(x, y_final, marker='o', mec='r', mfc='w', label='acc of final model')
# plt.plot(x, y_best_eval, marker='*', ms=10, label='highest acc of models during evaluation')
# # plt.plot(x, y_best_eval, marker='x', color='green', ms=10, label='model with highest acc during evaluation')
# plt.legend()  # 让图例生效
#
# plt.xlabel("Max number of Features")
# plt.ylabel("Accuracy(%)")
# plt.title("Performance of models with DecisionTree ")
# plt.savefig("DecisionTree.png")
# plt.show()

# plt.savefig("DecisionTree.png")

# 特征统计
# list1 = [18, 34, 54, 123, 124, 131, 142]
# list2 = [18, 33, 48, 109, 123, 137, 153]
# list3 = [18, 33, 63, 109, 123, 131, 153]
# list4 = [17, 18, 36, 109, 123, 133, 153]
# list5 = [18, 25, 30, 33, 84, 109, 123]
# list6 = [11, 18, 33, 109, 123, 141, 153]
# list7 = [18, 33, 45, 97, 109, 123, 153]
# list8 = [4, 47, 55, 77, 105, 133, 143]
# list9 = [18, 39, 61, 109, 112, 123, 133]
# list10 = [18, 35, 51, 61, 63, 109, 123]
# list11 = [10, 18, 35, 61, 109, 123, 134]
# list12 = [18, 61, 109, 123, 133, 153, 163]
# list13 = [18, 61, 78, 90, 109, 123, 153]
# list14 = [18, 37, 61, 109, 123, 129, 145]
# list15 = [10, 18, 60, 61, 79, 109, 123]

# list1 = [23, 51, 54, 76, 97, 100, 118, 133]
# list2 = [15, 23, 51, 76, 96, 100, 118, 154]
# list3 = [6, 17, 36, 51, 76, 96, 100, 118]
# list4 = [25, 32, 51, 54, 76, 96, 100, 118]
# list5 = [17, 51, 76, 96, 100, 118, 132, 154]
# list6 = [13, 26, 51, 58, 76, 96, 100, 118]
# list7 = [40, 51, 76, 96, 100, 102, 118, 141]
# list8 = [40, 51, 76, 96, 100, 118, 131, 132]
# list9 = [26, 51, 69, 76, 96, 100, 118, 132]
# list10 = [14, 15, 25, 34, 76, 118, 132, 138]
# list11 = [17, 28, 51, 76, 96, 100, 118, 149]
# list12 = [25, 33, 51, 66, 76, 100, 118, 158]
# list13 = [36, 51, 76, 96, 97, 100, 118, 132]
# list14 = [36, 51, 76, 92, 96, 100, 118, 157]
# list15 = [24, 33, 51, 70, 76, 100, 118, 129]

list1 = [17, 24, 40, 41, 48, 105, 119, 122, 136, 154]
list2 = [40, 41, 48, 54, 61, 83, 104, 122, 136, 154]
list3 = [17, 40, 41, 48, 76, 102, 122, 136, 137, 154]
list4 = [24, 40, 41, 48, 61, 84, 117, 122, 136, 154]
list5 = [23, 24, 40, 41, 48, 105, 122, 127, 136, 154]
list6 = [2, 24, 40, 41, 48, 105, 122, 124, 136, 154]
list7 = [24, 40, 41, 48, 105, 122, 125, 136, 152, 154]
list8 = [24, 40, 41, 48, 49, 105, 122, 136, 137, 154]
list9 = [15, 24, 40, 41, 48, 74, 122, 131, 136, 154]
list10 = [16, 24, 40, 41, 48, 122, 124, 134, 136, 154]
list11 = [24, 34, 40, 41, 48, 62, 122, 123, 136, 154]
list12 = [40, 41, 44, 48, 56, 77, 122, 136, 143, 154]
list13 = [40, 41, 48, 56, 115, 118, 122, 136, 151, 154]
list14 = [9, 14, 16, 40, 41, 48, 63, 122, 136, 154]
list15 = [5, 30, 40, 41, 48, 71, 75, 122, 136, 154]


# list1 = [8, 9, 14, 26, 41, 72, 83, 92, 134]
# list2 = [41, 57, 61, 97, 99, 107, 134, 147, 159]
# list3 = [3, 41, 57, 61, 67, 134, 151, 156, 158]
# list4 = [33, 41, 57, 61, 67, 114, 124, 134, 156]
# list5 = [6, 16, 32, 62, 69, 107, 134, 147, 162]
# list6 = [20, 21, 33, 41, 57, 67, 122, 134, 158]
# list7 = [31, 33, 41, 57, 67, 134, 138, 140, 158]
# list8 = [41, 57, 59, 61, 67, 109, 134, 147, 158]
# list9 = [41, 57, 61, 67, 109, 134, 135, 147, 158]
# list10 = [41, 57, 61, 67, 86, 94, 109, 134, 158]
# list11 = [11, 17, 23, 41, 57, 67, 127, 134, 158]
# list12 = [36, 41, 48, 55, 57, 67, 104, 134, 158]
# list13 = [10, 17, 30, 41, 49, 57, 67, 134, 158]
# list14 = [9, 41, 57, 67, 105, 119, 132, 134, 158]
# list15 = [22, 41, 57, 67, 97, 98, 134, 136, 158]

# list = []
# list.append(list1)
# list.append(list2)
# list.append(list3)
# list.append(list4)
# list.append(list5)
# list.append(list6)
# list.append(list7)
# list.append(list8)
# list.append(list9)
# list.append(list10)
# list.append(list11)
# list.append(list12)
# list.append(list13)
# list.append(list14)
# list.append(list15)
#
# dict = {}
# for i in list:
#     for x in i:
#         dict[x] = dict.get(x, 0) + 1
#
# dict = sorted(dict.items(), key=lambda x: x[1], reverse=True)
# for i in dict:
#     # print("{}:{}".format(i[0],i[1]))
#     print(i[0])
#     # print(i[1])
# # print(list)


def load_data(data_path):
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
    return data

#统计特征在良性/恶性中的平均值
data = load_data("data_test.csv")
# temp = [136, 40, 41, 48, 15, 154, 18, 109, 6, 21, 43, 61, 76, 90, 118, 122, 134, 161, 51, 100, 123, 57, 67, 96, 158, 33]
# temp = [17,24,153,47,44,105,132,23,97,133,147,25,36,1,9,10,16]
# temp = [26,27,35,50,53,54,56,60,63,66,68,107,111,124,131,137,156]
temp = [162,163]
temp_mal = []
temp_beni = []
mal = 0
beni = 0
for i in range(len(temp)):
    temp_mal.append(0)
    temp_beni.append(0)

for line in data:
    if line[-1] == 0:
        beni += 1
        for i in range(len(temp)):
            temp_beni[i] += line[temp[i] - 1]

    else:
        mal += 1
        for i in range(len(temp)):
            temp_mal[i] += line[temp[i] - 1]

# print(mal)
# print(beni)
for i in range(len(temp)):
    print("{} - {}".format(temp_mal[i] / mal, temp_beni[i] / beni))
    # print(temp_mal[i]/mal)
    # print(temp_beni[i]/beni)