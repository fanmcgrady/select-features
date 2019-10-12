import extract_n_gram as NGram
import extract_parser_features as Parser


class Extract():
    def __init__(self, sum_of_file, topnum_byte_feature_dict, count_byte_feature_dict, topnum_op_feature_dict=None,
                 count_op_feature_dict=None, N=4):
        self.features = []
        self.sum_of_file = sum_of_file
        self.topnum_byte_feature_dict = topnum_byte_feature_dict
        # self.topnum_op_feature_dict = topnum_op_feature_dict
        self.count_byte_feature_dict = count_byte_feature_dict
        # self.count_op_feature_dict = count_op_feature_dict
        self.N = N

    def __call__(self, file):
        self.features.append(Parser.extract(file))
        self.features.append(
            NGram.extract(file, self.sum_of_file, self.topnum_byte_feature_dict, self.count_byte_feature_dict))
        return self.features