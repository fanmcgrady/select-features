import random

import numpy as np

from utility import reward as cls


# action space 中的最后一个动作为终止

# 自己构建的环境
class MyEnv:
    def __init__(self, state_size, max, data, classifier):
        self.state_size = state_size
        self.action_size = state_size + 1  # 包含一个终止动作
        self.max = max  # 最多选取max个特征，超出直接终止
        self.data = data
        self.classifier = classifier
        self.dict = {}

        self.reset()

    def random_action(self):
        while True:
            action = random.randint(0, self.action_size - 1)
            if action == self.action_size - 1 or self.state[action] == 0:
                break
        return action

    def step(self, action_index):
        # if action_index == self.action_size - 1:  # 终止
        #     self.done = True
        # else:
        #     self.state[action_index] = 1
        #     self.count += 1
        #     if self.count == self.max_count:  # 已经到达选择数量上线
        #         self.done = True

        self.state[action_index] = 1
        self.count += 1
        if self.count == self.max_count:  # 已经到达选择数量上线
            self.done = True

            # reward 默认为0
            # if current_count>self.max:
            #     reward = self.max - current_count
            # else:
        reward = self.get_reward()
        if reward == -1:
            # print("no flag")
            reward = cls.get_reward(self.state, self.data, self.classifier)
            self.add_dict(reward)

        # reward = random.random()*100
        return np.array(self.state), reward, self.done

    def reset(self):
        self.state = [0 for _ in range(self.state_size)]
        self.max_count = min(self.max, self.state_size)  # 最大特征数
        self.count = 0  # 当前已经选取的特征数
        self.done = False
        return np.array(self.state)

    def render(self):
        print("This is me: {}".format(self.state))

    def get_reward(self):
        temp = [str(x) for x in self.state]
        temp = '.'.join(temp)
        reward = self.dict.get(temp, -1)
        return reward

    def add_dict(self, reward):
        temp = [str(x) for x in self.state]
        temp = '.'.join(temp)
        self.dict[temp] = reward
