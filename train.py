# Importing necessary Libraries
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

import joblib

labels = []
data_file = open('Dataset/Training_Dataset.arff').read()
data_list = data_file.split('\r\n')
data = np.array(data_list)
data_1 = [i.split(',') for i in data]
data_1 = data_1[0:-1]
for i in data_1:
    labels.append(i[30])
data_1 = np.array(data_1)
features = data_1[:-1]

#Choosing only the relevant features from the dataset
features = features[:, [0, 1, 2, 3 , 4, 5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 22, 24, 25, 27, 29]]
