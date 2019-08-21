from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import *  # NOQA

from chainerrl.action_value import ActionValue
from future import standard_library

standard_library.install_aliases()

from cached_property import cached_property
import chainer
from chainer import cuda
from chainer import functions as F
import numpy as np


class DiscreteActionValue(ActionValue):
    """Q-function output for discrete action space.

    Args:
        q_values (ndarray or chainer.Variable):
            Array of Q values whose shape is (batchsize, n_actions)
    """

    def __init__(self, q_values, q_values_formatter=lambda x: x):
        assert isinstance(q_values, chainer.Variable)
        self.xp = cuda.get_array_module(q_values.data)
        self.q_values = q_values
        self.n_actions = q_values.data.shape[1]
        self.q_values_formatter = q_values_formatter

    @cached_property
    def greedy_actions(self):
        return chainer.Variable(
            self.q_values.data.argmax(axis=1).astype(np.int32))

    @cached_property
    def greedy_actions_with_state(self):
        data = self.q_values.data.astype(np.float)
        print("data: ", data, len(data))
        print("state: ", self.state, len(self.state))
        while True:
            action = np.argmax(data, axis=1)[0]
            print("action:", action)

            if action != len(self.state) and self.state[action] == 1:
                data[0][action] = -100000
            else:
                break
        # if action == len(self.state):
        #     action = -1

        # print("q is {}, action is {}".format(data, action))

        return chainer.Variable(np.array([action]).astype(np.int32))
        # return chainer.Variable(np.array([-1]).astype(np.int32))
        # print(self.q_values.data.argmax(axis=1).astype(np.int32))
        # return chainer.Variable(
        #     self.q_values.data.argmax(axis=1).astype(np.int32))

    @cached_property
    def max(self):
        with chainer.force_backprop_mode():
            return F.select_item(self.q_values, self.greedy_actions)

    def sample_epsilon_greedy_actions(self, epsilon):
        assert self.q_values.data.shape[0] == 1, \
            "This method doesn't support batch computation"
        if np.random.random() < epsilon:
            return chainer.Variable(
                self.xp.asarray([np.random.randint(0, self.n_actions)],
                                dtype=np.int32))
        else:
            return self.greedy_actions

    def evaluate_actions(self, actions):
        return F.select_item(self.q_values, actions)

    def compute_advantage(self, actions):
        return self.evaluate_actions(actions) - self.max

    def compute_double_advantage(self, actions, argmax_actions):
        return (self.evaluate_actions(actions) -
                self.evaluate_actions(argmax_actions))

    def compute_expectation(self, beta):
        return F.sum(F.softmax(beta * self.q_values) * self.q_values, axis=1)

    def load_state(self, state):
        self.state = state

    def __repr__(self):
        return 'DiscreteActionValue greedy_actions:{} q_values:{}'.format(
            self.greedy_actions.data,
            self.q_values_formatter(self.q_values.data))

    @property
    def params(self):
        return (self.q_values,)

    def __getitem__(self, i):
        return DiscreteActionValue(
            self.q_values[i], q_values_formatter=self.q_values_formatter)
