# 说明
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

# TODO
1. 收集样本
1. 修改Reward，尝试设置指标数与准确率的比重
1. 两种终止尝试如何设置
1. 实验对比，复现其他论文结果
1. GPU
1. check out the following paper for feature selection:
    * Schultz, et al., 2001: http://128.59.14.66/sites/default/files/binaryeval-ieeesp01.pdf
    * Kolter and Maloof, 2006: http://www.jmlr.org/papers/volume7/kolter06a/kolter06a.pdf
    * Shafiq et al., 2009: https://www.researchgate.net/profile/Fauzan_Mirza/publication/242084613_A_Framework_for_Efficient_Mining_of_Structural_Information_to_Detect_Zero-Day_Malicious_Portable_Executables/links/0c96052e191668c3d5000000.pdf
    * Raman, 2012: http://2012.infosecsouthwest.com/files/speaker_materials/ISSW2012_Selecting_Features_to_Classify_Malware.pdf
    * Saxe and Berlin, 2015: https://arxiv.org/pdf/1508.03096.pdf
1. 过滤掉单个指标分类70%的指标

# 疑问
1. IDF
   * 小d为出现了某个字节码短序列的文件总数