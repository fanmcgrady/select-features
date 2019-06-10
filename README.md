# 毕业设计
数据预处理：generate data/
1. 把样本解压到generate data/
1. 运行screen samples.py，删除不能正常解析的文件
1. 运行select dll.py
1. 运行main.py，在根目录下保存data.csv

训练：
1. 入口是start.py
2. reward的计算方式和分类器在classifier.py里修改
3. read_data.py用来分析result下的文件
4. test.py里是画图和特征统计

# TODO
1. 收集样本
1. 修改Reward，尝试设置指标数与准确率的比重
1. 两种终止尝试如何设置
1. 实验对比，复现其他论文结果
