# 代码结构说明
1. generate data目录是样本预处理
    1. 把样本解压到generate data/
    1. 运行screen samples.py，删除不能正常解析的文件
    1. 运行select dll.py
    1. 运行main.py，在根目录下保存data.csv
1. utility目录是继承自chainerrl的强化学习库
1. 训练：
    1. 入口是start.py
    2. reward的计算方式和分类器在classifier.py里修改
    3. read_data.py用来分析result下的文件
    4. test.py里是画图和特征统计
1. 204个结构特征选取的方式参考如下论文:
    * Schultz, et al., 2001: http://128.59.14.66/sites/default/files/binaryeval-ieeesp01.pdf
    * Kolter and Maloof, 2006: http://www.jmlr.org/papers/volume7/kolter06a/kolter06a.pdf
    * Shafiq et al., 2009: https://www.researchgate.net/profile/Fauzan_Mirza/publication/242084613_A_Framework_for_Efficient_Mining_of_Structural_Information_to_Detect_Zero-Day_Malicious_Portable_Executables/links/0c96052e191668c3d5000000.pdf
    * Raman, 2012: http://2012.infosecsouthwest.com/files/speaker_materials/ISSW2012_Selecting_Features_to_Classify_Malware.pdf
    * Saxe and Berlin, 2015: https://arxiv.org/pdf/1508.03096.pdf
