import sys
import numpy
import pandas
import sklearn
import os
import tkinter as tk
from tkinter import messagebox
import sys
import pandas as pd

import pandas
from pandas.plotting import scatter_matrix
from sklearn import model_selection
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier

##DUOMENYS
data=pandas.read_csv("fit.csv")
input_data=data[['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med',
                                             'intarv_time_max',
                                             'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up',
                                             'intarv_time_min_up',
                                             'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                                             'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min',
                                             'bytes_payload_range',
                                             'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up',
                                             'bytes_payload_l4_min_up', 'bytes_payload_range_up',
                                             'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                                             'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow',
                                             'duration_flow_up',
                                             'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                                             'duration_bulkmode_up', 'duration_bulkmode_down', 'qouta_bulkmode',
                                             'qouta_bulkmode_upstream', 'qouta_bulkmode_downstream',
                                             'time_in_idle_mode', 'time_in_idle_mode_upstream', 'time_in_idle_mode_downstream',
                                             'time_in_idle_mode_qouta', 'time_in_idle_mode_qouta_up',
                                             'time_in_idle_mode_qouta_down']]
output_data=data[['website']]
test=pandas.read_csv("testavimas.csv")   #test2 twit, test1 fb
testav=test[['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med',
                                             'intarv_time_max',
                                             'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up',
                                             'intarv_time_min_up',
                                             'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                                             'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min',
                                             'bytes_payload_range',
                                             'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up',
                                             'bytes_payload_l4_min_up', 'bytes_payload_range_up',
                                             'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                                             'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow',
                                             'duration_flow_up',
                                             'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                                             'duration_bulkmode_up', 'duration_bulkmode_down', 'qouta_bulkmode',
                                             'qouta_bulkmode_upstream', 'qouta_bulkmode_downstream',
                                             'time_in_idle_mode', 'time_in_idle_mode_upstream', 'time_in_idle_mode_downstream',
                                             'time_in_idle_mode_qouta', 'time_in_idle_mode_qouta_up',
                                             'time_in_idle_mode_qouta_down']]
#print(input_data)
validation_size=0.5 # Testavimo dydis
seed=50
X_train, X_validation, Y_train, Y_validation=model_selection.train_test_split(input_data, output_data, test_size=validation_size, random_state=seed)
scoring='accuracy'

models = []
models.append(('LR', LogisticRegression()))
models.append(('LDA', LinearDiscriminantAnalysis()))
models.append(('KNN', KNeighborsClassifier()))
models.append(('CART', DecisionTreeClassifier()))
models.append(('NB', GaussianNB()))
models.append(('SVM', SVC()))
models.append(('RFC', RandomForestClassifier()))


input_trains, input_test, expected_output_train, expected_output_test=model_selection.train_test_split(input_data, output_data, test_size=0.50, random_state=42)
rf=RandomForestClassifier(n_estimators=3)
rf.fit(input_trains, expected_output_train)
accuracy=rf.score(input_test, expected_output_test)
print("Accuracy: {}".format(accuracy))
pred=rf.predict(testav)
print(pred)
prd=RandomForestClassifier(n_estimators=10, random_state=123456)
prd.fit(input_trains, expected_output_train)
prdresults=prd.predict(testav)
accuracy2=prd.score(input_test, expected_output_test)
print(accuracy2)
print(prdresults)
try:
    os.remove("resultsfile.txt")
except:
    print("file not found")
numpy.savetxt('resultsfile.txt', prdresults, fmt='%10.0f',delimiter='\t')

file=open('resultsfile.txt', 'r')
results=file.read()
one=""
facebookcount=0
twittercount=0
for result in results:
    if(result.__contains__('5')):
        one+="Facebook "
        facebookcount+=1
    if(result.__contains__('3')):
        one+="Twitter "
        twittercount+=1
highest=max(facebookcount, twittercount)
if(highest==facebookcount):
    browsed="Facebook"
if(highest==twittercount):
    browsed="Twitter"

def help():
    messagebox.askquestion('Help', 'Just press button "button" and you will see where you were browsing that session :)')
def sparameters():
    messagebox.showinfo('Full review', one)
def letssee():
    labbel2=tk.Label(window, text="You browsed in: ", font=(0, 10))
    labbel2.place(relx=.40, rely=.3)
    labbel3=tk.Label(window, text=browsed, font=(0,20))
    labbel3.place(relx=.36, rely=.4)
    parameters=tk.Button(window, text="Full review", command=sparameters)
    parameters.place(relx=.0, rely=.5)
window=tk.Tk()
window.title("Classifier")
window.geometry('500x350')
labbel=tk.Label(window, text="Want to find out where you browsed?", font=(0,10))
labbel.place(relx=.32, rely=.1)
help=tk.Button(window, text="HELP", command=help, width=10)
help.place(relx=.80, rely=.9)
button1=tk.Button(window, text="Let's see!", width=10, command=letssee)
button1.place(relx=.45, rely=.2)
window.mainloop()


#results = []
#names = []
#for name, model in models:
#	kfold = model_selection.KFold(n_splits=2, random_state=seed)
#	cv_results = model_selection.cross_val_score(model, X_train, Y_train, cv=kfold, scoring=scoring)
#	results.append(cv_results)
#	names.append(name)
#	msg = "%s: %f (%f)" % (name, cv_results.mean(), cv_results.std())
#	print(msg)
#




# Predictionai ir algoritmu taikymas
#nb="Algoritmas su geriausiu accuracy"
#nb.fit(X_train, Y_train)
#predictions=nb.predict(X_validation)
#print(accuracy_score(Y_validation, predictions))
#print(confusion_matrix(Y_validation, predictions))
#print(classification_report(Y_validation, predictions))
#testrez=nb.predict(test_data) # Predictionas
#print(testrez)
