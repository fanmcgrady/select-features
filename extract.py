import extract_parser_features as Parser
import extract_n_gram as NGram


class Extract():
    def __init__(self):
        self.features = []

    def __call__(self, file):
        self.features.append(Parser.extract(file))
        self.features.append(NGram.extract(file))
        return self.features
