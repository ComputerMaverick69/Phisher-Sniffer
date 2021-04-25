# Purpose - To print the training data and check the parsing logic for it.
# Note: This file is not a part of the codepath which is used by the Chrome extension for making a decision.

import numpy as np
from features_extraction import DIRECTORY_NAME, LOCALHOST_PATH

with open(LOCALHOST_PATH + DIRECTORY_NAME + '/Dataset/Training_Dataset.arff') as f:
    file = f.read()
data_list = file.split('\n')

# print(data_list)
print("/////////////////////////////////")

data = np.array(data_list)
data_1 = [i.split(',') for i in data]

print("Data 1 before indexing - ", data_1)
print ("Length of Data 1 - ", len(data_1))
print ("////////////////////////////////")

data_1 = data_1[0:-1]

print ("Data 1 after indexing - ", data_1)
print ("Length of Data 1 - ", len(data_1))

# for i in data1:
#    labels.append(i[30])
data_1 = np.array(data_1)

print ("Converted to np array - ", data_1)
print ("Number of columns in a row - ", len(data_1[0]))
print ("Shape of Data 1 - ", data_1.shape)
print ("////////////////////////////////")

features = data_1[:, :-1]

print ("Features array - ", features)
print ("Number of columns in a row - ", len(features[0]))