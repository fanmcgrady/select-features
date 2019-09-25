from utility.classifier import get_reward

if __name__ == '__main__':
    # 要选取的指标索引
    origin = [162, 163]
    # 样本csv文件
    data_path = "generate_data/data_test.csv"

    state = []
    for i in range(163):
        state.append(0)
    for j in origin:
        state[j] = 1

    print(state)

    get_reward(state, data_path)
