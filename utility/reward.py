import numpy as np
from sklearn import metrics
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC

from utils import load_csv


# 分类器方法枚举类，可以在这里添加其他方法
class Classifier():
    RandomForest = RandomForestClassifier(random_state=0, n_estimators=500)
    SVC = SVC(kernel='rbf', probability=True, gamma='auto')
    KNN = KNeighborsClassifier()
    GaussianNB = GaussianNB()
    DT = tree.DecisionTreeClassifier()

def get_reward(state,  # state: 标记指标是否选取的数组
               data_path,  # data_path:
               classifier=Classifier.KNN):  # 分类器

    count = len(state)  # 本次选的指标数目

    data = load_csv(data_path)

    for i in reversed(range(len(state) - 1)):
        if state[i] == 0:
            count -= 1
            for index in range(len(data)):
                del data[index][i]

    if count == 0:
        return 0
    label = np.array(data)[:, -1].astype(np.float64)
    data = np.array(data)[:, :-1].astype(np.float64)

    return classify(data, label, classifier)


def classify(data, label, classifier):
    # x_train, x_test, y_train, y_test = train_test_split(data, label, test_size=0.3, random_state=0)
    x_train, x_test, y_train, y_test = train_test_split(data, label, test_size=0.2, random_state=0)

    classifier.fit(x_train, y_train)

    # scores = cross_val_score(classifier, x_train, y_train, cv=10)

    y_predict = classifier.predict(x_test)
    result = metrics.accuracy_score(y_test, y_predict)
    # false_positive_rate, true_positive_rate, thresholds = metrics.roc_curve(y_test,y_predict)
    # roc_auc = metrics.auc(false_positive_rate, true_positive_rate)
    return result
    # plt.title('Receiver Operating Characteristic')
    # plt.plot(false_positive_rate, true_positive_rate, 'b',
    #          label='AUC = %0.2f' % roc_auc)
    # plt.legend(loc='lower right')
    # plt.plot([0, 1], [0, 1], 'r--')
    # plt.xlim([0, 0.3])
    # plt.ylim([0, 1])
    # plt.ylabel('True Positive Rate')
    # plt.xlabel('False Positive Rate')
    # plt.show()
    # return  roc_auc
    # return scores.mean()
    # print(scores.mean())
    # return precision_score(y_test, y_predict), recall_score(y_test, y_predict)



