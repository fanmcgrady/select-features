from utility import reward
from utility.reward import Classifier

if __name__ == '__main__':
    data = "comparation/paper1.csv"
    state = []

    for i in range(204):
        state.append(1)

    print(reward.get_reward(state, data, Classifier.KNN))
    print(reward.get_reward(state, data, Classifier.RandomForest))
    print(reward.get_reward(state, data, Classifier.DT))
    print(reward.get_reward(state, data, Classifier.GaussianNB))
    print(reward.get_reward(state, data, Classifier.SVC))

    # 我们的
    # KNN   0.9931619900966753
    # RandomForest  0.9992926196651734
    # DT    0.9974062721056355
    # GNB   0.5699127564253714
    # SVC   0.5779297335534073

    # Raman et al.
    # KNN   0.9450601273284602
    # RandomForest  0.9983494458854044
    # DT    0.996934685215751
    # GNB   0.4402263617071445
    # SVC   0.7948597029002594

    # PE-Miner

    # Kim

    # 白师兄
