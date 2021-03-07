import os
import re
import glob
import numpy as np

from concurrent.futures import ThreadPoolExecutor




def dir_and_app(appfp):
    """
    given one app fp, return the directory to the app, as well as the app name
    
    appfp --> an app's filepath
    return --> a list: [directory to app, appname]
    """
    
    direc, app = os.path.split(appfp)
    if ".gml.bz2" in app:
        app = app.replace(".gml.bz2", "")
        return [direc, app]
    elif ".apk" in app:
        app = app.replace("apk", "")
        return [direc, app]
    elif "m2v_walks.txt" in app:
        app = app.replace("m2v_walks.txt", "")
        return [direc, app]
    else:
        return appfp
    
    
    

def permutation(lst):
    if len(lst) == 0:
        return []

    if len(lst) == 1:
        return [lst]

    l = []

    for i in range(len(lst)):
        m = lst[i]
        remLst = lst[:i] + lst[i+1:]

    for p in permutation(remLst):
        l.append([m] + p)
    return l

def list_files(directory):
    """
    returns a list of all the files in that directory, with the directory appended to it
    """
    
    return [os.path.join(directory, item) for item in os.listdir(directory)]



def useful_functions(a, d, dx):
    """
    some useful functions for a decompiled APK


    a --> APK object
    d --> array of DalvikVMFormat object
    dx --> analysis object


    """


    ### attributes and methods for a --> APK Class
    test_obj = a.get_permissions()
    # Returns all requested permissions.
    test_obj = a.get_requested_aosp_permissions_details()
    # Returns requested aosp permissions with details.
    test_obj = a.get_libraries()
    # Return the android:name attributes for libraries
    display(type(test_obj))
    ### attributes and methods for d --> DalvikVMFormat
    test_d = d[0].get_all_fields()
    # Return a list of field items
    test_d = d[0].get_classes()
    # Returns all classes --> returns a ClassDefItem
    test_d = d[0].get_fields()
    # Returns all field objects --> EncodedField Object
    test_d = d[1].get_len_methods()
    # Return the number of methods
    test_d = d[1].get_methods()
    # Returns all method objects --> EncodedMethod Objects
    test_d = d[1].get_strings()
    # returns all Strings
    # test_d
    # for item in test_d:
    #     if len(item.get_name()) > 1:
    #         print(item.get_name())
    ### Prints the fields, or classes, or methods, (can be used for EDA)
    # ct = 0
    # for item in d[0].get_fields():
    #     if ct < 600:
    #         print(item)
    #         ct+= 1
    #     else:
    #         break


def get_graph_info(digraph):
    """
    Takes in a networkx digraph and output some statistics for the graph

    params: digraph --> networkx digraph object
    prints: --> number of nodes, and edges.
    """

    print("Number of nodes in this graph is: ", len(digraph.nodes()))
    print("Number of edges in this graph is: ", len(digraph.edges()))




# get paths to smali files
def get_path(app):
    paths = []

    for root, dirs, files in os.walk(app, topdown=False):
        for name in files:
            path = os.path.join(root, name)
            if ".smali" in path:
                paths.append(path)
    return paths

# get directory name w/in the directory
def get_dir_name(fp):
    dir_names = glob.glob(fp)
    return dir_names

# get txt of smali files
def get_txt(fp):
    file = open(fp, 'r')
    txt = file.read()
    return txt

# returns a list of all txt files for 1 app
def app_smali_to_txt(app_smali_fp):
    # get all txt files given
    txt_lst = []
    for i in app_smali_fp:
        txt = get_txt(i)
        txt_lst.append(txt)
    return txt_lst


def all_txt_dir(dir_lst):
    # get all smali files given a directory
    fp_lst = []
    for i in dir_lst:
        app_smali_fp = get_path(i)
        fp_lst.append(app_smali_fp)

    all_txt = []
    for i in fp_lst:
        # returns a list of txt of an app
        lst = app_smali_to_txt(i)
        all_txt.append(lst)

    return all_txt

def fp_builder(rootdir):
    """
    gets to the root, as defined by the user

    rootdir --> the folder to stop at
    """

    current = os.getcwd()
    folders = []
    path, folder = os.path.split(current)
    while True:
        if folder != "":
            folders.append(folder)
            path,folder = os.path.split(path)
        else:
            break
    folders.reverse()

    root_fp = "/"
    for folder in folders:
        if folder != rootdir: #build fp until rootdir is reached
            root_fp = os.path.join(root_fp, folder)
        else:
            root_fp = os.path.join(root_fp, rootdir)
            break

    return root_fp


def get_to_directory(root, to_apks):
    """
    getting to a directory from root
    to_apks --> list of paths of directories to get to a folder
    """

    directory = fp_builder(root)
    for folder in to_apks:
        directory = os.path.join(directory, folder)

    return directory




# A
def A(txt):
    # get any invokes
    invoke = '(invoke)(.*?)(;)'
    apis = re.findall(invoke, txt)
    api_lst = []

    ### get api ###
    for i in apis:
        api = i[1].split("L")[-1]
        api_lst.append(api)

    ### get family ###
    family_lst = []
    for i in api_lst:
        family = i.split("/")[0][1:]
        family_lst.append(family)

    ### get invoke types ###
    invoke_lst = []
    for i in apis:
        invoke_type = i[1].split(" ")[0][1:]
        invoke_lst.append(invoke_type)

    # for distinct returns
    return set(api_lst), set(family_lst), set(invoke_lst)
