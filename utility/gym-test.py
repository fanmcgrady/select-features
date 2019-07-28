# 《先进计算模型》深度强化学习 hello world 程序
import logging
import sys

import chainer
import chainer.functions as F
import chainer.links as L
import chainerrl
import gym
import numpy as np

from hook.plot_hook import PlotHook


# 使用强化学习模型，创建一个agent智能体


def createAgentDQN(env):
    # 构建Q Network
    class QFunction(chainer.Chain):
        def __init__(self, obs_size, n_actions, n_hidden_channels=50):
            super().__init__()
            with self.init_scope():
                self.l0 = L.Linear(obs_size, n_hidden_channels)
                self.l1 = L.Linear(n_hidden_channels, n_hidden_channels)
                self.l2 = L.Linear(n_hidden_channels, n_actions)

        def __call__(self, x, test=False):
            """
            Args:
                x (ndarray or chainer.Variable): An observation
                test (bool): a flag indicating whether it is in test mode
            """
            h = F.tanh(self.l0(x))
            h = F.tanh(self.l1(h))
            return chainerrl.action_value.DiscreteActionValue(self.l2(h))

    obs_size = env.observation_space.shape[0]
    n_actions = env.action_space.n
    q_func = QFunction(obs_size, n_actions)
    q_func.to_gpu(0)

    # Use Adam to optimize q_func. eps=1e-2 is for stability.
    optimizer = chainer.optimizers.Adam(eps=1e-2)
    optimizer.setup(q_func)

    # Set the discount factor that discounts future rewards.
    gamma = 0.95

    # Use epsilon-greedy for exploration
    explorer = chainerrl.explorers.ConstantEpsilonGreedy(
        epsilon=0.3, random_action_func=env.action_space.sample)

    # DQN uses Experience Replay.
    # Specify a replay buffer and its capacity.
    replay_buffer = chainerrl.replay_buffer.ReplayBuffer(capacity=10 ** 6)

    # Since observations from CartPole-v0 is numpy.float64 while
    # Chainer only accepts numpy.float32 by default, specify
    # a converter as a feature extractor function phi.
    phi = lambda x: x.astype(np.float32, copy=False)

    # Now create an graduation_agent that will interact with the environment.
    agent = chainerrl.agents.DoubleDQN(
        q_func, optimizer, replay_buffer, gamma, explorer,
        replay_start_size=32, update_interval=1,
        target_update_interval=100, phi=phi)

    return agent


def trainingAgent(agent, env):
    # train agent
    print('开始训练agent')

    n_episodes = 200
    max_episode_len = 200

    for i in range(1, n_episodes + 1):
        obs = env.reset()
        reward = 0
        done = False
        R = 0  # return (sum of rewards)
        t = 0  # time step
        while not done:
            # Uncomment to watch the behaviour
            # env.render()
            action = agent.act_and_train(obs, reward)
            obs, reward, done, _ = env.step(action)
            R += reward
            t += 1
        print("done")
        if i % 10 == 0:
            print('episode:', i,
                  'R:', R)
        agent.stop_episode_and_train(obs, reward, done)

    print('Agent training finished！')


class randomAgent():
    """The world's simplest graduation_agent!"""

    def __init__(self, action_space):
        self.action_space = action_space

    def act(self, observation):
        return self.action_space.sample()

    def stop_episode(self):
        pass

    def load(self, model_name):
        pass


average_q = PlotHook('Average Q')
average_loss = PlotHook('Average Loss', plot_index=1)


def plot_average_q(env, agent, t):
    if t % 10 == 0:
        stat = agent.get_statistics()
        d = {}
        d[stat[0][0]] = stat[0][1]
        average_q.plot(t, d)


def plot_average_loss(env, agent, t):
    if t % 10 == 0:
        stat = agent.get_statistics()
        d = {}
        d[stat[1][0]] = stat[1][1]
        average_loss.plot(t, d)


# 开始训练
def train_agent(env, rounds=20000):
    np.random.seed(123)
    env.seed(123)

    agent = createAgentDQN(env)

    # train agent
    # n_episodes = rounds
    # max_episode_len = env.maxturns
    # for i in range(1, n_episodes + 1):
    #     obs = env.reset()
    #     reward = 0
    #     done = False
    #     R = 0  # return (sum of rewards)
    #     t = 0  # time step
    #     while not done and t < max_episode_len:
    #         # Uncomment to watch the behaviour
    #         # env.render()
    #         action = agent.act_and_train(obs, reward)
    #         obs, reward, done, _ = env.step(action)
    #         R += reward
    #         t += 1
    #     if i % 10 == 0:
    #         print('episode:', i,
    #               'R:', R)
    #     agent.stop_episode_and_train(obs, reward, done)
    # print('Agent Finished.')

    # test agent
    # for i in range(10):
    #     obs = env.reset()
    #     done = False
    #     R = 0
    #     t = 0
    #     while not done and t < max_episode_len:
    # #        env.render()
    #         action = agent.act(obs)
    #         obs, r, done, _ = env.step(action)
    #         R += r
    #         t += 1
    #     print('test episode:', i, 'R:', R)
    #     agent.stop_episode()
    # print('RL completed!')

    # agent.save(name)

    gym.undo_logger_setup()
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='')

    chainerrl.experiments.train_agent_with_evaluation(
        agent, env,
        steps=rounds,  # Train the graduation_agent for this many rounds steps
        max_episode_len=200,  # Maximum length of each episodes
        eval_interval=1000,  # Evaluate the graduation_agent after every 1000 steps
        eval_n_runs=10,  # 100 episodes are sampled for each evaluation
        outdir='cart',  # Save everything to 'result' directory
        step_hooks=[plot_average_q, plot_average_loss],
        successful_score=100)

    return agent


# 使用gym的CartPole游戏
env = gym.make('CartPole-v0')

agent = train_agent(env)

# 随机的方法创建智能体
# agent = randomAgent(env.action_space)

# 强化学习的方法创建智能体
# agent = createAgentDQN(env)
# 现场训练模型
# trainingAgent(agent, env)
# 加载训练好的模型
# agent.load("cart")

# 循环运行10次游戏，对agent进行测试
for i_episode in range(10):
    observation = env.reset()
    R = 0
    for t in range(200):
        env.render()
        action = agent.act(observation)
        observation, reward, done, info = env.step(action)
        R += reward
        if done:
            print("{}:Episode finished after {} timesteps, reward {}".format(i_episode, t + 1, R))
            break
    agent.stop_episode()
