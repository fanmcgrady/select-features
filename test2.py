import utils

if __name__ == '__main__':
    # data_path = "generate_data/parser.csv"

    # 1、生成样本文件
    # utils.save_csv(data_path, utils.generate_data())

    # 2、测试提取特征逐个的成功率
    # data = utils.load_csv(data_path)
    # for i in range(len(data[0])):
    #     reward = utils.get_features_reward(data_path, [i])
    #     with open("get_features_reward.txt", 'a') as f:
    #         f.write("The reward of the feature {} is {}".format(i, reward))
    #         if reward > 0.7:
    #             f.write(" > 0.7")
    #         f.write("\n")

    utils.judge_data_directory()
