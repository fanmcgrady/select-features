import argparse
import os
import time

import chainer
import chainer.functions as F
import chainer.links as L
import numpy as np
from chainer import optimizers
from chainerrl import replay_buffer, explorers

import utils
from utility import env as Env, agent as DDQN, action_value as ActionValue
from utility.reward import Classifier

# linux命令行使用，复制以下命令即可执行
# nohup python start.py --result-file KNN_10feature_64_plus_32.txt --max-feature 10 --gpu 1 --layer1-nodenum 64 --layer2-nodenum 32>training_log.txt 2>&1 &

parser = argparse.ArgumentParser()
parser.add_argument('--result-file', type=str, default='result.txt')
parser.add_argument('--max-feature', type=int, default=10)
parser.add_argument('--gpu', type=int, default=-1)
parser.add_argument('--training-data', type=str, default='training_data_4grams.csv')
parser.add_argument('--layer1-nodenum', type=int, default=64)
parser.add_argument('--layer2-nodenum', type=int, default=32)
args = parser.parse_args()

# 可变参数
data = "data/" + args.training_data
feature_number = 604  # 特征总数量
feature_max_count = args.max_feature  # 选取的特征数目大于该值时，reward为0，用于当特征数目在该范围内时，成功率最多可以到达多少
MAX_EPISODE = 1000
net_layers = [args.layer1_nodenum, args.layer2_nodenum]
classifier = Classifier.KNN

# 每一轮逻辑如下
# 1. 初始化环境，定义S和A两个list，用来保存过程中的state和action。进入循环，直到当前这一轮完成（done == True）
# 2. 在每一步里，首先选择一个action，此处先用简单的act()代替
# 3. 接着env接收这个action，返回新的state，done和reward，当done==False时，reward=0，当done==True时，reward为模型的准确率
# 4. 如果done==True，那么应该把当前的S、A和reward送到replay buffer里（replay也应该在此时进行），往replay buffer里添加时，
#    每一对state和action都有一个reward，这个reward应该和env返回的reward（也就是该模型的acc）和count有关。

# 用这个逻辑替代原来的my_train的逻辑，只需要把agent加入即可，agent应该是不需要修改的
episode_reward = []
evaluate_reward = []


class QFunction(chainer.Chain):
    def __init__(self, obs_size, n_actions, n_hidden_channels=None):
        super(QFunction, self).__init__()
        if n_hidden_channels is None:
            n_hidden_channels = net_layers
        net = []
        inpdim = obs_size
        for i, n_hid in enumerate(n_hidden_channels):
            net += [('l{}'.format(i), L.Linear(inpdim, n_hid))]
            # net += [('norm{}'.format(i), L.BatchNormalization(n_hid))]
            net += [('_act{}'.format(i), F.relu)]
            net += [('_dropout{}'.format(i), F.dropout)]
            inpdim = n_hid

        net += [('output', L.Linear(inpdim, n_actions))]

        with self.init_scope():
            for n in net:
                if not n[0].startswith('_'):
                    setattr(self, n[0], n[1])

        self.forward = net

    def __call__(self, x, test=False):
        """
        Args:
            x (ndarray or chainer.Variable): An observation
            test (bool): a flag indicating whether it is in test mode
        """
        for n, f in self.forward:
            if not n.startswith('_'):
                x = getattr(self, n)(x)
            elif n.startswith('_dropout'):
                x = f(x, 0.1)
            else:
                x = f(x)

        return ActionValue.DiscreteActionValue(x)


def evaluate(eval_env, agent, current):
    for i in range(1):
        state = eval_env.reset()
        terminal = False
        count = 0
        while not terminal:
            action, q = agent.act(state)
            count += 1
            state, reward, terminal = eval_env.step(action)

            if terminal:
                state_human = [i + 1 for i in range(len(state)) if state[i] == 1]
                evaluate_reward.append(reward)
                utils.log(args.result_file,
                          "evaluate episode:{}, reward = {}, state count = {}, state = {}\n"
                          .format(current, reward, len(state_human), state_human))

                agent.stop_episode()


def train_agent(env, agent, eval_env):
    for episode in range(MAX_EPISODE):
        state = env.reset()
        terminal = False
        reward = 0
        count = 0
        while not terminal:
            action, q, ga = agent.act_and_train(
                state, reward)  # 此处action是否合法（即不能重复选取同一个指标）由agent判断。env默认得到的action合法。
            count += 1
            state, reward, terminal = env.step(action)
            # print("episode:{}, action:{}, greedy action:{}, reward = {}".format(episode, action, ga, reward))

            if terminal:
                state_human = [i + 1 for i in range(len(state)) if state[i] == 1]
                # utils.log(args.result_file, "train episode:{}, reward = {}, state count = {}, state = {}"
                #           .format(episode, reward, len(state_human), state_human))

                agent.stop_episode_and_train(state, reward, terminal)
                episode_reward.append(reward)
                if (episode + 1) % 10 == 0 and episode != 0:
                    evaluate(eval_env, agent, (episode + 1) / 10)


def create_agent(env):
    state_size = env.state_size
    action_size = env.action_size
    q_func = QFunction(state_size, action_size)

    start_epsilon = 1.
    end_epsilon = 0.3
    decay_steps = 20
    explorer = explorers.LinearDecayEpsilonGreedy(
        start_epsilon, end_epsilon, decay_steps,
        env.random_action)

    opt = optimizers.Adam()
    opt.setup(q_func)

    rbuf_capacity = 5 * 10 ** 3
    minibatch_size = 16

    steps = 1000
    replay_start_size = 20
    update_interval = 10
    betasteps = (steps - replay_start_size) // update_interval
    rbuf = replay_buffer.PrioritizedReplayBuffer(rbuf_capacity, betasteps=betasteps)

    phi = lambda x: x.astype(np.float32, copy=False)

    agent = DDQN.DoubleDQN(q_func, opt, rbuf, gamma=0.99,
                           explorer=explorer, replay_start_size=replay_start_size,
                           target_update_interval=10,  # target q网络多久和q网络同步
                           update_interval=update_interval,
                           phi=phi, minibatch_size=minibatch_size,
                           target_update_method='hard',
                           soft_update_tau=1e-2,
                           episodic_update=False,
                           gpu=args.gpu,  # 设置是否使用gpu
                           episodic_update_len=16)
    return agent


def train():
    # 训练时使用
    env = Env.MyEnv(feature_number, feature_max_count, data, classifier)
    # 测试时使用
    eval_env = Env.MyEnv(feature_number, feature_max_count, data, classifier, test=True)

    agent = create_agent(env)
    train_agent(env, agent, eval_env)

    return env, agent


if __name__ == '__main__':
    start_time = time.time()

    train()

    # 统计训练用时，保留两位小数
    elapsed = (round((time.time() - start_time) / 3600, 2))

    # 用于计算本次训练中最大的准确率以及平均准确率
    max_reward = max(episode_reward)
    average_reward = 0
    for i in range(len(episode_reward)):
        average_reward += episode_reward[i]
    average_reward = average_reward / len(episode_reward)

    # 评估结果
    max_evaluate_reward = max(evaluate_reward)
    average_evaluate_reward = 0
    for i in range(len(evaluate_reward)):
        average_evaluate_reward += evaluate_reward[i]
    average_evaluate_reward = average_evaluate_reward / len(evaluate_reward)

    # 写入训练日志结果
    utils.log(args.result_file, "The max reward of this train:{}, the average reward of this train:{}"
              .format(max_reward, average_reward))

    # 写入测试日志结果
    utils.log(args.result_file, "The max reward of this evaluate:{}, the average reward of this evaluate:{}"
              .format(max_evaluate_reward, average_evaluate_reward))

    # 训练时间
    utils.log(args.result_file, "Training elapsed:{} hours".format(elapsed))

    # 修改文件名
    os.rename(args.result_file,
              "{}-{}-{}-{}".format(args.result_file, max_evaluate_reward, average_evaluate_reward, elapsed))
