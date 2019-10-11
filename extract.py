import extract_n_gram as NGram
import extract_parser_features as Parser


class Extract():
    def __init__(self, sum_of_file, topnum_byte_feature_dict, all_byte_feature_dict, topnum_op_feature_dict, all_op_feature_dict, N):
        self.features = []
        self.sum_of_file = sum_of_file
        self.topnum_byte_feature_dict = topnum_byte_feature_dict
        self.all_byte_feature_dict = all_byte_feature_dict
        self.topnum_op_feature_dict = topnum_op_feature_dict
        self.all_op_feature_dict = all_op_feature_dict
        self.N = N

    def __call__(self, file):
        self.features.append(Parser.extract(file))
        self.features.append(NGram.extract(file, self.sum_of_file, self.topnum_byte_feature_dict, self.all_byte_feature_dict, self.topnum_op_feature_dict, self.all_op_feature_dict, self.N))
        return self.features