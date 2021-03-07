from src import utils
from src.model import model as md
from src.data import data_androguard
from src.analysis import andro_analysis
from src.data import mamadroid_implementation as mama
from src.data import commongraph as coco
from scipy.sparse import lil_matrix
from scipy.sparse import save_npz
from scipy.sparse import load_npz
from sklearn.model_selection import train_test_split
from gensim.models.doc2vec import Doc2Vec


import sys
#from config import data_params
import numpy as np
import pandas as pd

import os, sys, inspect
import json


import os, sys, inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)



DATA_PARAMS = 'config/data_params.json'
MODEL_PARAMS = 'config/model.json'
TEST_PARAMS = 'config/test.json'
FEATURE_PARAMS = "config/features.json"
MAMA_PARAMS = "config/mamadroid_params.json"


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))


def load_params(fp):
    with open(fp) as fh:
        param = json.load(fh)

    return param


def main(targets):
    """
    runs the targets
    targets --> a list of targets
    """

    #["data", "feature", "model", "train", "test"]
    if "data" in targets:
        data_config = load_params(DATA_PARAMS)
        data_androguard.train_txt(data_config["malware_dir"], data_config["popular_dir"], data_config["random_dir"], data_config["app_id_out"])



    elif "feature" in targets:
        feature_config = load_params(FEATURE_PARAMS)
        train, test = (feature_config["trainFP"], feature_config["testFP"], feature_config["malware_dir"], feature_config["popular_dir"], feature_config["random_dir"])
        
        apps = train + test
        
        for app in apps:
            data_androguard.wrapper(app, feature_config["commonFP"], feature_config["metapathsFP"], feature_config["walksFP"])



    elif 'test' in targets:
        with open(TEST_PARAMS) as fh:
            test_cfg = json.load(fh)
            
        benign_dir = test_cfg['test_benign']
        malicious_dir =test_cfg['test_malicious']
        
        apks = utils.list_files(benign_dir) + utils.list_files(malicious_dir)
        np.random.shuffle(apks)
        split = round(len(apks) * 0.8)
        train = apks[:split]
        test = apks[split:]
        

        target = test_cfg["test_outputs"]
        # get txt with labels:
            
        txt = test_cfg["app_label"]
        if os.path.exists(txt):
            os.remove(txt)
            data_androguard.train_txt(malicious_dir, benign_dir, benign_dir, target)
        else:
            data_androguard.train_txt(malicious_dir, benign_dir, benign_dir, target)
        
        print(train)
        # create features using wrapper
        apks = train + test
        
        for apk in apks:
            data_androguard.wrapper(apk, target, target, target)

        # build a common graph, run metapath2vec
        data = pd.read_csv(txt)
        X, y = coco.metapath2vec(target, train, target, txt, target, test_cfg["modelFP"], testing = True)
        
        md.actuals(X, y, X, y)
        
        
    elif "mamadroid" in targets:

        with open(MAMA_PARAMS) as fh:
            mama_cfg = json.load(fh)
            
        
            
        malicious_apks = os.listdir(mama_cfg["malware_dir"])
        popular_apks = os.listdir(mama_cfg["popular_dir"])
        random_apks = os.listdir(mama_cfg["random_dir"])
        target = mama_cfg["out_dir"]
        
#         # currently use vectorize, have to test with concurrency
#         mama.create_markovs(mama_cfg["malware_dir"], target, "PACKAGE")
#         mama.create_markovs(mama_cfg["malware_dir"], target, "FAMILY")
#         mama.create_markovs(mama_cfg["popular_dir"], target, "PACKAGE")
#         mama.create_markovs(mama_cfg["popular_dir"], target, "FAMILY")
#         mama.create_markovs(mama_cfg["random_dir"], target, "PACKAGE")
#         mama.create_markovs(mama_cfg["random_dir"], target, "FAMILY")
        
#         directories = [target]
#         mama.create_X(directories)

        # perform PCA and classify
        X_family = load_npz(mama_cfg["family_npz"])
        X_package = load_npz(mama_cfg["package_npz"])
        y_family = np.loadtxt(mama_cfg["family_label"])
        y_package = np.loadtxt(mama_cfg["package_label"])
        
        
        family_mode = model.baseline(X_family
                                     , X_package
                                     , y_family
                                     , y_package
                                     , [10]
                                     , mama_cfg["mamadroid_results"])
        
    elif "cocodroid" in targets:
        with open(DATA_PARAMS) as fh: 
            coco_cfg = json.load(fh)
            
        train, test = train_test(coco_cfg["trainFP"], coco_cfg["testFP"], coco_cfg["malware_dir"], coco_cfg["popular_dir"], coco_cfg["random_dir"])

        # get X and y
        X_train, y_train = coco.metapath2vec(coco_cfg["commonFP"],
                                 train,
                                coco_cfg["metapathsFP"],
                                coco_cfg["app_ids_txt"],
                                coco_cfg["walksFP"], 
                                 coco_cfg["cocodroid_model_path"],
                                             reduced = True, 
                                             subset = True)
        
        X_test, y_test = coco.metapath2vec_testing(coco_cfg["commonFP"], 
                                                 coco_cfg["cocodroid_model_path"],
                                                  coco_cfg["walksFP"],
                                                   coco_cfg["metapathsFP"],
                                                  test, 
                                                   coco_cfg["app_ids_txt"])
        
        
        
        # classification process using models in baseline
        md.actuals(X_train, y_train, X_test, y_test, coco_cfg["model_results"], "cocodroid")
        
        
        
        
        
        
    elif "doc2vec" in targets:
        with open(DATA_PARAMS) as fh: 
            d2v_cfg = json.load(fh)
        
        train, test = train_test(d2v_cfg["trainFP"], d2v_cfg["testFP"], d2v_cfg["malware_dir"], d2v_cfg["popular_dir"], d2v_cfg["random_dir"])
        
        
        wrapper_vec = np.vectorize(data_androguard.wrapper)
        wrapper_vec(np.array(train), d2v_cfg["commonFP"], d2v_cfg["metapathsFP"], d2v_cfg["walksFP"])
        
        # if model exists, no need to do another:
        if (not os.path.exists(d2v_cfg["doc2vec_model_path"])) & (not os.path.exists(d2v_cfg["doc2vec_labels"])):
            model, labels = data_androguard.doc2vec_train(train, d2v_cfg["walksFP"], d2v_cfg["app_ids_txt"])
            model.save(d2v_cfg["doc2vec_model_path"])
            np.savetxt(d2v_cfg["doc2vec_labels"], labels)
        else:
            print("Model exists, will load the model instead.........")
            model = Doc2Vec.load(d2v_cfg["doc2vec_model_path"])
            labels = np.loadtxt(d2v_cfg["doc2vec_labels"])

            
        X_train = [model.docvecs[i] for i in range(len(model.docvecs))]
        y_train = labels
        
        X_test, y_test = data_androguard.doc2vec_test(test, 
                                      d2v_cfg["walksFP"],
                                     d2v_cfg["app_ids_txt"],
                                     model,
                                     d2v_cfg["commonFP"],
                                     d2v_cfg["metapathsFP"],
                                     d2v_cfg["walksFP"])
        
        
        print(len(X_test))
        print(len(y_test))
        
        md.actuals(X_train, y_train, X_test, y_test, d2v_cfg["model_results"], "doc2vec")
        
        
        


    return None

def train_test(trainFP, testFP, malwareFP, popularFP, randomFP):
    """
    gets train and test arrays
    
    """  
    malware_apks = utils.list_files(malwareFP)
    popular_apks = utils.list_files(popularFP)
    random_apks = utils.list_files(randomFP)
    apks = malware_apks + popular_apks + random_apks

    if (not os.path.exists(trainFP)) & (not os.path.exists(testFP)):
        apks = [utils.dir_and_app(app)[1] for app in apks]
        np.random.shuffle(apks)
        split = round(len(apks) * 0.8)
        train = apks[:split]
        test = apks[split:]
        np.savetxt(trainFP, train, fmt = "%s")
        np.savetxt(testFP, test, fmt = "%s")

    else:
        train = np.loadtxt(trainFP, dtype = object)
        test = np.loadtxt(testFP, dtype = object)
        
    return [train, test]


if __name__ == "__main__":
    target = sys.argv[1:]
    main(target)

#     with open(MAMA_PARAMS) as fh:
#         mama_cfg = json.load(fh)
        
#     for item in mama_cfg.values():
#         print(os.path.exists(item))
    
    
