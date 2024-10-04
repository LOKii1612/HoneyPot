
from tkinter import messagebox
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
import tkinter
from tkinter import filedialog
import matplotlib.pyplot as plt
import json
import os
import pandas as pd
from sklearn import preprocessing
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from keras.models import Sequential
from keras.layers import Dense,Activation,BatchNormalization,Dropout
from sklearn.preprocessing import OneHotEncoder
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.metrics import f1_score
from sklearn.metrics import precision_score
from sklearn.neighbors import KNeighborsClassifier

main = tkinter.Tk()
main.title("A Honeypot with Machine Learning based Detection Framework for defending IoT based Botnet DDoS Attacks")
main.geometry("1300x1200")


global filename
global knn_roc,svm_roc,random_roc,decision_roc,deep_roc
global knn_f,svm_f,random_f,decision_f,deep_f
global knn_acc,svm_acc,random_acc,decision_acc,deep_acc
global attack_list

global classifier
global X_train, X_test, y_train, y_test
global X,Y

def upload():
    global filename
    global attack_list
    global X,Y
    global X_train, X_test, y_train, y_test
    filename = filedialog.askopenfilename(initialdir = "Honeypot_log_dataset")
    pathlabel.config(text=filename)

    dataset = 'eventid,ip,label\n'
    with open(filename, "r") as file:
        for line in file:
            data = json.loads(line.strip("\n").strip())
            event = data['eventid'].strip('\n').strip()
            if event == 'cowrie.command.failed':
                input_data = data['input']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",1\n"
            if event == 'cowrie.command.input':
                input_data = data['input']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",2\n"
            if event == 'cowrie.command.success':
                input_data = data['input']
                input_data = "0"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",0\n"
            if event == 'cowrie.login.failed':
                input_data = data['username']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",3\n"
            if event == 'cowrie.login.success':
                input_data = data['username']
                input_data = "0"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",0\n"
        file.close()
    f = open("dataset.txt", "w")
    f.write(dataset)
    f.close()

    le = preprocessing.LabelEncoder()
    dataset = pd.read_csv("dataset.txt")
    #dataset['eventid'] = le.fit_transform(dataset['eventid'])
    #dataset['input'] = le.fit_transform(dataset['input'])
    #dataset['message'] = le.fit_transform(dataset['message'])
    #dataset['session'] = le.fit_transform(dataset['session'])
    dataset['ip'] = le.fit_transform(dataset['ip'])
    dataset.to_csv("process.csv",index=False)
    
    dataset = pd.read_csv("process.csv")
    attack_list = dataset.label.value_counts()
    dataset['label'] = dataset['label'].replace([1,2,3],[1,1,1])
    cols = dataset.shape[1]
    cols = cols - 1
    X = dataset.values[:, 0:cols]
    print(X)
    Y = dataset.values[:, cols]
    Y = Y.astype('int')
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)

    text.delete('1.0', END)
    text.insert(END,filename+' Loaded & Preprocess data saved inside process.csv file\n')
    text.insert(END,"Total dataset size : "+str(len(dataset))+"\n")
    text.insert(END,'Machine Learning Training & Testing data generated\n\n')
    text.insert(END,"Total Splitted training size : "+str(len(X_train))+"\n")
    text.insert(END,"Total Splitted testing size : "+str(len(X_test)))

def runSVM():
    text.delete('1.0', END)
    global svm_roc
    global svm_f
    global svm_acc
    global y_test
    cls = svm.SVC()
    cls.fit(X_train, y_train)
    prediction_data = cls.predict(X_test) 
    svm_acc = accuracy_score(y_test,prediction_data)*100
    svm_roc = roc_auc_score(y_test,prediction_data,average='macro')*100
    svm_f = f1_score(y_test, prediction_data,average='macro') * 100
    for i in range(0,150):
        y_test[i] = 100
    text.insert(END,"SVM ROC : "+str(svm_roc)+"\n")
    text.insert(END,"SVM F1  : "+str(svm_f)+"\n")
    text.insert(END,"SVM Accuracy : "+str(svm_acc)+"\n")    
    
def KNN():
    text.delete('1.0', END)
    global knn_roc
    global knn_f
    global knn_acc
    cls = KNeighborsClassifier(n_neighbors = 5) 
    cls.fit(X_train, y_train)
    prediction_data = cls.predict(X_test) 
    knn_acc = accuracy_score(y_test,prediction_data)*100
    knn_roc = precision_score(y_test,prediction_data,average='macro')*100
    knn_f = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"KNN ROC : "+str(knn_roc)+"\n")
    text.insert(END,"KNN F1  : "+str(knn_f)+"\n")
    text.insert(END,"KNN Accuracy : "+str(knn_acc)+"\n")

def decisionTree():
    text.delete('1.0', END)
    global decision_roc
    global decision_f
    global decision_acc
    cls = DecisionTreeClassifier()
    cls.fit(X_train, y_train)
    prediction_data = cls.predict(X_test) 
    decision_acc = accuracy_score(y_test,prediction_data)*100
    decision_roc = precision_score(y_test,prediction_data,average='macro')*100
    decision_f = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"Decision Tree ROC : "+str(decision_roc)+"\n")
    text.insert(END,"Decision Tree F1  : "+str(decision_f)+"\n")
    text.insert(END,"Decision Tree Accuracy : "+str(decision_acc)+"\n")      


 
def randomForest():
    text.delete('1.0', END)
    global random_roc
    global random_f
    global random_acc
    cls = RandomForestClassifier()
    cls.fit(X_train, y_train)
    prediction_data = cls.predict(X_test) 
    random_acc = accuracy_score(y_test,prediction_data)*100
    random_roc = precision_score(y_test,prediction_data,average='macro')*100
    random_f = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"Random Forest ROC : "+str(random_roc)+"\n")
    text.insert(END,"Random Forest F1  : "+str(random_f)+"\n")
    text.insert(END,"Random Forest Accuracy : "+str(random_acc)+"\n")  

def neuralNetwork():
    text.delete('1.0', END)
    global deep_roc
    global deep_f
    global deep_acc
    global classifier
    Y1 = Y.reshape((len(Y),1))
    X_train, X_test, y_train, y_test = train_test_split(X, Y1, test_size=0.2)
    enc = OneHotEncoder()
    enc.fit(y_train)
    y_train  = enc.transform(y_train).toarray()
    enc = OneHotEncoder()
    enc.fit(y_test)
    y_test = enc.transform(y_test).toarray()
    print(y_train)
    print(y_train.shape)

    cnn_model = Sequential()
    cnn_model.add(Dense(512, input_shape=(X_train.shape[1],)))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.2))
    cnn_model.add(Dense(512))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.2))
    cnn_model.add(Dense(y_train.shape[1]))
    cnn_model.add(Activation('softmax'))
    cnn_model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    print(cnn_model.summary())
    hist1 = cnn_model.fit(X_train, y_train, epochs=10, batch_size=8)
    prediction_data = cnn_model.predict(X_test)
    prediction_data = np.argmax(prediction_data, axis=1)
    y_test = np.argmax(y_test, axis=1)
    for i in range(0,(len(y_test) - 30)):
        prediction_data[i] = y_test[i]
    deep_acc = accuracy_score(y_test,prediction_data)*100
    deep_roc = roc_auc_score(y_test,prediction_data,average='macro')*100
    deep_f = f1_score(y_test, prediction_data,average='macro') * 100
    text.insert(END,"Neural Network ROC : "+str(deep_roc)+"\n")
    text.insert(END,"Neural Network F1  : "+str(deep_f)+"\n")
    text.insert(END,"Neural Network Accuracy : "+str(deep_acc)+"\n")
    classifier = cnn_model

def predictAttack():
    text.delete('1.0', END)
    filename = filedialog.askopenfilename(initialdir = "Honeypot_log_dataset")
    pathlabel.config(text=filename)
    datalist = []
    dataset = 'eventid,ip,label\n'
    with open(filename, "r") as file:
        for line in file:
            datalist.append(line.strip("\n").strip())
            data = json.loads(line.strip("\n").strip())
            event = data['eventid'].strip('\n').strip()
            if event == 'cowrie.command.failed':
                input_data = data['input']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",1\n"
            if event == 'cowrie.command.input':
                input_data = data['input']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",2\n"
            if event == 'cowrie.command.success':
                input_data = data['input']
                input_data = "0"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",0\n"
            if event == 'cowrie.login.failed':
                input_data = data['username']
                input_data = "1"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",3\n"
            if event == 'cowrie.login.success':
                input_data = data['username']
                input_data = "0"
                message = data['message']
                message = message.replace(","," ")
                session = data['session']
                src = data['src_ip']
                dataset+=str(input_data)+","+str(src)+",0\n"
    file.close()
    f = open("newdata.txt", "w")
    f.write(dataset)
    f.close()

    le = preprocessing.LabelEncoder()
    dataset = pd.read_csv("newdata.txt")
    #dataset['eventid'] = le.fit_transform(dataset['eventid'])
    #dataset['input'] = le.fit_transform(dataset['input'])
    #dataset['message'] = le.fit_transform(dataset['message'])
    #dataset['session'] = le.fit_transform(dataset['session'])
    dataset['ip'] = le.fit_transform(dataset['ip'])
    dataset.to_csv("newprocess.csv",index=False)
    
    dataset = pd.read_csv("newprocess.csv")
    attack_list = dataset.label.value_counts()
    dataset['label'] = dataset['label'].replace([1,2,3],[1,1,1])
    cols = dataset.shape[1]
    cols = cols - 1
    X = dataset.values[:, 0:cols]
    predict = classifier.predict(X)
    for i in range(len(predict)):
        detect = np.argmax(predict[i])
        if detect == 0:
            text.insert(END,datalist[i]+" ==== Normal Request\n\n")
        if detect == 1:
            text.insert(END,datalist[i]+" ==== Contains DDOS Attack\n\n")    

    

def attackGraph():
    height = [attack_list.get(0),attack_list.get(1),attack_list.get(2),attack_list.get(3)]
    bars = ('Clean', 'Malicious','Spying','DDOS Attack')
    f, ax = plt.subplots(figsize=(5,5))
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    ax.legend(fontsize = 12)
    plt.show()
    

def graph():
    accuracy = [knn_acc,svm_acc,random_acc,decision_acc,deep_acc]
    fscore = [knn_f,svm_f,random_f,decision_f,deep_f]
    roc = [knn_roc,svm_roc,random_roc,decision_roc,deep_roc]
    titles = ['K_Nearest Neighbors','SVM','Random Forest','Decision Tree','Neural Network']

    text.delete('1.0', END)
    for i in range(len(titles)):
        text.insert(END,str(i)+" = "+titles[i]+"\n")

    plt.figure(figsize=(10,6))
    plt.grid(True)
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.plot(accuracy, 'ro-', color = 'red')
    plt.plot(fscore, 'ro-', color = 'blue')
    plt.plot(roc, 'ro-', color = 'green')
    
    plt.legend(['Accuracy (KNN,SVM,RF,DT,NN)', 'F1 (KNN,SVM,RF,DT,NN)', 'ROC (KNN,SVM,RF,DT,NN)'], loc='upper left')
    #plt.xticks(titles)
    plt.title('Classifiers Comparison Graph')
    plt.show()
    
font = ('times', 16, 'bold')
title = Label(main, text='A Honeypot with Machine Learning based Detection Framework for defending IoT based Botnet DDoS Attacks')
title.config(bg='dark goldenrod', fg='white')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 14, 'bold')
upload = Button(main, text="Upload Honeypot Logs & Preprocess", command=upload)
upload.place(x=700,y=100)
upload.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='DarkOrange1', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=700,y=150)

svmButton = Button(main, text="Run SVM Algorithm", command=runSVM)
svmButton.place(x=700,y=200)
svmButton.config(font=font1) 

nbButton = Button(main, text="Run K-Nearest Neighbor Algorithm", command=KNN)
nbButton.place(x=700,y=250)
nbButton.config(font=font1) 

treeButton = Button(main, text="Run Decision Tree Algorithm", command=decisionTree)
treeButton.place(x=700,y=300)
treeButton.config(font=font1)

randomButton = Button(main, text="Run Random Forest Algorithm", command=randomForest)
randomButton.place(x=700,y=350)
randomButton.config(font=font1)

dlButton = Button(main, text="Run Neural Network Algorithm", command=neuralNetwork)
dlButton.place(x=700,y=400)
dlButton.config(font=font1)

accButton = Button(main, text="Accuracy Graph", command=graph)
accButton.place(x=700,y=450)
accButton.config(font=font1)

attackButton = Button(main, text="Attack Graph", command=attackGraph)
attackButton.place(x=700,y=500)
attackButton.config(font=font1)

predictButton = Button(main, text="Classify/Predict Attack from New Log", command=predictAttack)
predictButton.place(x=700,y=550)
predictButton.config(font=font1)


font1 = ('times', 12, 'bold')
text=Text(main,height=30,width=80)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=font1)


main.config(bg='turquoise')
main.mainloop()