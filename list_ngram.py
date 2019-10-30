import utils
from extract_n_gram import count_byte_DF

paths = [utils.BENI_PATH, utils.MAL_PATH]
top_feature_dict, _ = count_byte_DF(paths, 4, 400)
ngrams_list = []
for i in range(204):
    ngrams_list.append(0)
for key in top_feature_dict.keys():
    ngrams_list.append(key)
print(ngrams_list)
print(len(ngrams_list))
with open('exper.txt', 'w') as f:
    f.write(str(ngrams_list))
