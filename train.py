# Importing necessary Libraries
from sklearn import tree
from config import DIRECTORY_NAME, LOCALHOST_PATH
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

import joblib

labels = []

with open(LOCALHOST_PATH + DIRECTORY_NAME + '/Dataset/Training_Dataset.arff') as f:
    data_file = f.read()
# data_file = open('/Dataset/Training_Dataset.arff').read()
data_list = data_file.split('\n')
data = np.array(data_list)
data_1 = [i.split(',') for i in data]
data_1 = data_1[0:-1]

for i in data_1:
    labels.append(i[30])

data_1 = np.array(data_1)

features = data_1[:, :-1]

#Choosing only the relevant features from the dataset
features = features[:, [0, 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 22, 24, 25, 27, 29]]

features = np.array(features).astype(np.float)

features_train = features
labels_train = labels

# # features_test = features[10000:]
# # labels_test = labels[10000:]

print("\n\n ""Random Forest Algorithm Results"" ")
classifier_4 = RandomForestClassifier(min_samples_split=7, verbose=True)
classifier_4.fit(features_train, labels_train)
importances_4 = classifier_4.feature_importances_
std_4 = np.std([tree.feature_importances_ for tree in classifier_4.estimators_], axis=0)
indices_4 = np.argsort(importances_4)[::-1]

# Print the feature ranking
print("\nFeature Ranking\n")
for f in range(features_train.shape[1]):
    print("%d. featured %d (%f)" % (f + 1, indices_4[f], importances_4[indices_4[f]]))

# predict_4 = classifier_4.predict(feature_test)
# print(classification_report(labels_test, predict_4))
# print('The Accuracy is:', accuracy_score(labels_test, predict_4))
# print(metrics.confusion_matrix(labels_test, predict_4))

# sys.setrecursionlimit(9999999)
joblib.dump(classifier_4, 'Classifier/rf.pkl', compress=9)