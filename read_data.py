import matplotlib.pyplot as plt

file = "result/DT_9.txt"
t_max = 0
e_max = 0
t_min = 100
e_min = 100

sum = 0
num = 0
evaluation = []
train = []
string = {}
with open(file, 'r') as f:
    count = 0
    while True:
        count += 1
        line = f.readline()
        if not line:
            break
        # print(line[0])
        if line[0] != 't' and line[0] != 'e':
            continue
        # 百分比读取
        index = line.index('=') + 4
        if line[index - 1] == ',':
            # print("{}:{}".format(count, 0))
            continue
        if line[index - 2] == '1':
            # print("{}:{}".format(count, 1))
            continue
        if line[index + 1] == ',':
            result = 10 * int(line[index])

        elif line[index + 2] == ',':
            result = 10 * int(line[index]) + int(line[index + 1])

        else:
            result = 10 * int(line[index]) + int(line[index + 1]) + 0.1 * int(line[index + 2]) + 0.01 * int(line[index + 3])
            if int(line[index + 4]) >= 5: result += 0.01

        # *100读取
        # index = line.index('=') + 2
        # if int(line[index]) == 0:
        #     print("{}:{}".format(count, 0))
        #     continue
        #
        # result = 10 * int(line[index]) + int(line[index + 1]) + 0.1 * int(line[index + 3]) + 0.01 * int(line[index + 4])
        # if int(line[index + 5]) >= 5: result += 0.01

        # print("{}:{}".format(count, result))

        if line[0] == 't':
            if result > 95: train.append(result)
            if result > t_max:    t_max = result
            if result < t_min:    t_min = result
            evaluation.append(result)
            string[result] = line
        if line[0] == 'e':
            sum += result
            num += 1
            evaluation.append(result)
            string[result] = line
            if result > e_max:    e_max = result
            if result < e_min:    e_min = result

    # print("t_max = {}, t_min = {}, e_max = {}, e_min = {}".format(t_max, t_min, e_max, e_min))
    # print(sum / num)
    # print(string)

    sort = {}

    sorted_dict= sorted(string.items(), key=lambda x: x[0], reverse=True)
    # print(sorted_dict)
    # count = 0
    for i in sorted_dict:
        sort[i[0]] = i[1]

    for k,v in sort.items():
        print("{}:{}".format(k,v))

    # print(sorted(zip(string.keys(), string.values())))

x = []
count = 1
train = evaluation
for i in train:
    x.append(count)
    count += 1
plt.figure()
plt.plot(x, train)
plt.show()
