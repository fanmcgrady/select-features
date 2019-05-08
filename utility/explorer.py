from chainerrl.explorers import epsilon_greedy

class LinearDecayEpsilonGreedy(epsilon_greedy.LinearDecayEpsilonGreedy):
    def select_action(self, state, t, greedy_action_func, action_value=None):
        pass