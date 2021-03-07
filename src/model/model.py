import numpy as np
import os

import numpy as np
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import normalize
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight


## plotting
import seaborn as sns 
import matplotlib.pyplot as plt


import sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from data import data_androguard




class model_creation:

    def __init__(self, model_type, Xtrain, ytrain, Xtest, ytest, output):
        self.X_train, self.y_train, self.X_test, self.y_test = Xtrain, ytrain, Xtest, ytest
        self.file = output


        if model_type == "baseline":
            self.init_baseline()

        elif model_type == "SVM":
            # https://scikit-learn.org/stable/modules/svm.html#using-the-gram-matrix
            # returns accuracy score
            self.acc = self.svm_model(self.X_train, self.y_train, self.X_test, self.y_test)

        elif model_type == "KNN":
            # https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.KNeighborsClassifier.html
            self.clf = KNeighborsClassifier(n_neighbors = 3)


    def init_baseline(self):
        '''
        baseline is MamaDroid, which uses Random Forests, 1NN, 3NN and SVM
        '''
        
        ## get class weights first, for unbalanced and biased classes
        
        weights = compute_class_weight(class_weight = "balanced", classes = np.unique(self.y_train), y = self.y_train)
        weight_dict = dict(zip(np.unique(self.y_train), self.y_train))
        self.file.write("\n\n")
        self.file.write("For the Random Forest Classifier: ")
        print("For the Random Forest Classifier: ")
        self.clf = RandomForestClassifier(n_estimators = 30, class_weight = weight_dict).fit(self.X_train, self.y_train)
        self.predict(self.X_test, self.y_test)
        
        
        self.file.write("\n\n")
        self.file.write("For the 1-NN Classifier: ")
        print("\n\n")
        print("For the 1-NN Classifier: ")
        self.clf = KNeighborsClassifier(n_neighbors = 1).fit(self.X_train, self.y_train)
        self.predict(self.X_test, self.y_test)
        

        self.file.write("\n\n")
        self.file.write("For the 3-NN Classifier: ")
        print("\n\n")
        print("For the 3-NN Classifier: ")
        self.clf = KNeighborsClassifier(n_neighbors = 3).fit(self.X_train, self.y_train)
        self.predict(self.X_test, self.y_test)
        
        
    def predict(self, X_test, y_test, plot =False):
        """
        predicts on X_test, using the classifier
        prints some scores: f1, elements from the confusion matrix
        
        X_test --> X used for testing, (n x m) matrix
        y_test --> labels, (n x 1) array
        plot --> if we want to see actual plots or not
        output --> output file
        """
        
        predictions = self.clf.predict(X_test)
        f1 = f1_score(y_true = y_test, y_pred = predictions)
        tn, fp, fn, tp = confusion_matrix(y_true =y_test, y_pred = predictions).ravel()
        
        self.file.write(("\nF1 score for this classifier: " + str(f1)))
        print("\nF1 score for this classifier: ", f1)
        
        self.file.write(("\n\nFrom the confusion matrix: \n     True Negatives = " + str(tn) 
             + "\n     False Positives = "+ str(fp) + "\n     False Negatives "+ str(fn) + "\n     True Positives"+ str(tp)))
        print("\n\nFrom the confusion matrix: \n    True Negatives = ", tn 
             , "\n     False Positives = ", fp, "\n     False Negatives ", fn, "\n     True Positives", tp)
        
        if plot == True:
            self.conf_matrix(y_test, predictions)



    def svm_model(self, X_train, y_train, X_test, y_test):
        '''
        SVM model
        '''

        X_train = np.array(X_train)
        y_train = np.array(y_train)

        # svm model
        self.clf = SVC(kernel='linear', C=1.0)

        # fit
        self.clf.fit(X_train, y_train)

        # predict
        y_pred = self.clf.predict(X_test)

        # accuracy score
        self.acc = accuracy_score(y_test, y_pred)

        # classification report: precision, recall, f1-score, support
        print(classification_report(y_test, y_pred))

        return self.acc
    
    def conf_matrix(self, y_test, pred_test):
        """
        Plots the confusion matrix from prediction 

        """
        # Creating a confusion matrix
        con_mat = confusion_matrix(y_test, pred_test)
        con_mat = pd.DataFrame(con_mat, range(2), range(2))

        #Ploting the confusion matrix
        plt.figure(figsize=(6,6))
        sns.set(font_scale=1.5) 
        sns.heatmap(con_mat, annot=True, annot_kws={"size": 16}, fmt='g', cmap='Blues', cbar=False)
        
        
        
        
    
def baseline(X_family, X_package, y_family, y_package, pcas, output_dir):
    """
    Baseline is the mamadroid model
    
    pcas --> list of components to try

    """
    
    for pca in pcas:
        # create output file:
        file_fp = os.path.join(output_dir, ("Baseline PCA: " + str(pca) + ".txt"))
        
        print("\n With PCA components = ", pca)
        pca = PCA(n_components = pca)
        X_family = normalize(X_family, norm = "l1", axis = 1)
        X_family_pca = pca.fit_transform(X_family.toarray())
        
        X_package = normalize(X_package, norm = "l1", axis = 1)
        X_package_pca = pca.fit_transform(X_package.toarray())
        
        
        X_family_train, X_family_test, y_family_train, y_family_test = train_test_split(X_family_pca, y_family, test_size = 0.15, shuffle = True)

        X_package_train, X_package_test, y_package_train, y_package_test = train_test_split(X_package_pca, y_package, test_size = 0.15, shuffle = True)
        
        with open(file_fp, "a") as file: 
            writeline = "For FAMILY mode, the scores are: \n"
            file.write(writeline)
            print(writeline)
            family = model_creation("baseline", 
                                    X_family_train, 
                                    y_family_train, 
                                    X_family_test, 
                                    y_family_test, file)
            
            writeline = "\nFor PACKAGE mode, the scores are: \n"
            file.write(writeline)
            print(writeline)
            package = model_creation("baseline", 
                                     X_package_train, 
                                     y_package_train, 
                                     X_package_test, 
                                     y_package_test, file)
            
        file.close()
        
        
    return "Done"

def actuals(X_train, y_train, X_test, y_test, output_dir = "", experiment = ""):
    """
    performs classification using X and y
    """
    
    file_fp = os.path.join(output_dir, (experiment + "_results.txt"))
    with open(file_fp, "a") as file:
        model = model_creation("baseline", X_train, y_train, X_test, y_test, file)
    file.close()
    return None



if __name__ == "__main__":
    print("main")
