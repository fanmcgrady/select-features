import utils

if __name__ == '__main__':
    data_path = "generate_data/parser.csv"

    # 1、生成样本文件
    # utils.save_csv(data_path, utils.generate_data())

    # 2、测试提取特征逐个的成功率
    utils.get_features_reward(data_path, [0])
