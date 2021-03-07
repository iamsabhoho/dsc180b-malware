import numpy as np
import regex as re
import networkx as nx
from stellargraph import StellarGraph
# import concurrent.futures
import multiprocessing
import glob

import pandas as pd
import numpy as np

import os


# getting to utils
import sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
import utils

POSSIBLE_FAMILIES = "Landroid,Lgoogle,Ljava,Ljavax,Lxml,Lapache,Ljunit,Ljson,Ldom".split(",")
POSSIBLE_PACKAGES = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/mamadrioid_intermediate_files/all_possible_packages.txt"
POSSIBLE_EDGES = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/mamadrioid_intermediate_files/all_possible_edges.txt"



def get_possible_packages():
    """
    obtains the list of possible packages for the latest API level, FOR PACKAGE MODE
    returns a list of possible packages. 
    """
    
    possible_packages = []
    with open(POSSIBLE_PACKAGES, 'r') as file:
        for line in file:
            line = "L" + line
            possible_packages.append(line.rsplit("."))
    file.close()
    return possible_packages
    

def get_possible_edges():
    """
    obtains the list of all possible edges according to the packages we have, for PACKAGE MODE
    """
    
    possible_edges = []
    with open(POSSIBLE_EDGES, 'r') as file:
        for line in file:
            sep = line.split()
            edge = (sep[0], sep[1])
            possible_edges.append(edge)
    file.close()
    return possible_edges

def get_possible_family_edges():
    """
    obtains the list of all possible edges created using FAMILY MODE
    """
    possible_edges = []
    for family1 in POSSIBLE_FAMILIES:
        for family2 in POSSIBLE_FAMILIES:
            possible_edges.append((family1, family2))
            
    return possible_edges

def get_package_family(kind, api):
    """
    gets a package or family from api
    
    kind --> string, FAMILY or PACKAGE
    api --> string of the api
    """
    package_fp = os.path.join(POSSIBLE_PACKAGES)
    possible_packages = []
    with open(package_fp, 'r') as file:
        for line in file:
            line = "L" + line
            possible_packages.append(line.split("."))
    file.close()

    if kind == "FAMILY":
        sep = api.split("/")[:1][0]
        if sep in POSSIBLE_FAMILIES:
            return sep
        else:
            return "self_defined"
       
    elif kind == "PACKAGE":
        
        for package in possible_packages:
            ct = 0
            for item in package:
                processed = item.replace("\n", "")
                if processed in api:
                    ct += 1
                else:
                    continue
            if (ct == len(package)) & (ct > 1):
                to_return = "/".join(package).replace("\n", "")
                return to_return
        if package == possible_packages[-1]:
            return "self_defined"


def edge_processing(edge, kind):
    """
    performs get_package_family on an edge
    edge --> a list that is an edge
    """
    new_edge = []
    for edg in edge:
        if type(edg) != int:
            new_edge.append(get_package_family(kind, edg))
        else:
            new_edge.append(edg)
    return new_edge


def get_markov(inFP, outFP, kind):

    
    """
    obtains the markov chain for one app
    
    inFP --> input file path (should be .gml.bz2)
    outFP --> output directory
    kind --> (str) FAMILY or PACKAGE
    
    """

    direc, app_name = utils.dir_and_app(inFP)
    outputfp = os.path.join(outFP, (app_name + "_" + kind + ".txt")) 
    if os.path.exists(outputfp):
        print("app ", inFP, " is already done!")

    else:
        try:
            networkx = nx.read_gml(inFP)
        except:
            return inFP + " might be broken!"
        
        nx_nodes = np.array(networkx.nodes())
        nx_edges = np.array(networkx.edges, dtype = object)
        
        # convert to package/family mode 
        vfunc = np.vectorize(get_package_family)
        newnodes = vfunc(kind, nx_nodes)
        new_edges = []
        for edge in nx_edges:
            new_edges.append(edge_processing(edge, kind))
        G = nx.MultiDiGraph()
        G.add_nodes_from(newnodes)
        G.add_edges_from(new_edges)
        stellar = StellarGraph.from_networkx(G)

        # step2: markov chain
        ## Set of possible states of the Markov chain is denoted as S
        ## If Sj and Sk are two connected states, Pjk denotes P(transition from Sj to Sk)
        ## Pjk is # occurances(Ojk), or edges(from j to k), divided by # of all occurrences
        ## Pjk = # of Edge(j, k) / # total edges
        if kind == "PACKAGE":
            possible_packages = get_possible_packages()
            S = ["/".join(item).strip() for item in possible_packages] + ["self_defined"]
            possible_edges = get_possible_edges()
        elif kind == "FAMILY":
            possible_packages = POSSIBLE_FAMILIES
            possible_edges = get_possible_family_edges()
            S = possible_packages + ["self_defined"]
        total_edges = stellar.number_of_edges()
        markov = []
        counts_nd_stuff = pd.Series(stellar.edges()).value_counts()


        for j in S:
            for k in S: ## we might have self calling loops
                edge = (j, k)
                try:
                    Pjk = counts_nd_stuff[edge]/total_edges
                    markov.append(Pjk)
                except ValueError:
                    markov.append(0)

        # build output fp and save
        if (round(sum(markov)) == 1) & (not os.path.exists(outputfp)):
            try:
                np.savetxt(outputfp, markov, fmt = "%s")
                print("the app: ", inFP, " is done!", "mode: ", kind)
                return (inFP + " IS FINISHED!")
            except:
                print("the app: ", inFP, " encountered errors!")


def create_markovs(inFP, targetdir, kind):
    """
    Creates markov chains based on the graphs in the directory. Calls get_markov a lot of times
    
    directory --> the directory containing the graphs
    """
    directory = os.listdir(inFP)
    vfunc = np.vectorize(get_markov)
    results = vfunc(np.array(directory), targetdir, kind)
    
    return ("Finished for directory: " + inFP + " and for kind: " + kind)

    
    

def create_X(directories):
    """
    
    Creates the big matrix X for the created markov chains
    
    
    directories --> should contain a list of directories containing ".txt" files, either family or package
    """
    now = datetime.now()
    files = []
    for directory in directories:
        for item in os.listdir(directory):
            files.append(item)


    files_fullfp = []
    for directory in directories:
        for item in os.listdir(directory):
            files_fullfp.append(os.path.join(directory, item))
            
            
    
    npz_output = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/mamadroid_intermediate_files/npz_output"
    information = pd.read_csv("/teams/DSC180A_FA20_A00/a04malware/personal-group03/intermediate_files/app_label_id.txt")
    family_fp = []
    family_labels = []
    package_fp = []
    package_labels = []

    for file in range(len(files)):
        filename = files[file]
        if ("_FAMILY.txt" in filename):
            to_check = filename.replace("_FAMILY.txt", "")
        elif ("_PACKAGE.txt" in filename):
            to_check = filename.replace("_PACKAGE.txt", "")

        label = information[information.app_fp.str.contains(to_check)].app_label.iloc[0]

        if "FAMILY" in filename:
            family_fp.append(files_fullfp[file])
            family_labels.append(label)
        elif "PACKAGE" in filename:
            package_fp.append(files_fullfp[file])
            package_labels.append(label)
            
    family_sparse = lil_matrix((len(family_fp), 100))
    for row in range(len(family_fp)):
        one_row = np.loadtxt(family_fp[row])
        if len(one_row) > 1:
            family_sparse[row] = one_row
            
            
    package_sparse = lil_matrix((len(package_fp), 51529))
    for row in range(len(package_fp)):
        one_row = np.loadtxt(package_fp[row])
        if len(one_row) > 1:
            package_sparse[row] = one_row
            
    family_sparse = family_sparse.tocsc()
    package_sparse = package_sparse.tocsc()
            
    save_npz(os.path.join("family_sparse.npz"), family_sparse)
    save_npz(os.path.join("package_sparse.npz"), package_sparse)
    
    print("Finished, took: " , (datetime.now() - now))
    
def add_onto_X(directory):
    return None
            
        

# def principal_components(X_fp, components):
#     """
#     gets the principal components of X
    
#     X_fp --> filepath to sparse matrix, should end with ".npz"
#     components --> integer, specifies how many components we want
    
#     returns the principal components required for classification
#     """
    
#     X = load_npz(X_fp)

    
    
#     return X_pca


    

if __name__ == "__main__":
    print("~ mamadroid ~")

    # file paths

    target = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/mamadroid_intermediate_files/markov_chains"

    
    # malware
    malware_dir = "/teams/DSC180A_FA20_A00/a04malware/apks/malware"
    malware_apks = [os.path.join(malware_dir, fp) for fp in os.listdir(malware_dir)]

    vfunc = np.vectorize(get_markov)
    directory = malware_apks

    # change directory and "FAMILY" to package as required

    results = vfunc(np.array(directory), target, "PACKAGE")
    print("malware package is finished!")
        


    

                
