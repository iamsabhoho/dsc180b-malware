from androguard import misc
from androguard import session
from stellargraph import StellarGraph
import networkx as nx
from androguard.core.analysis import auto
from datetime import datetime
import sys
import os
import pandas as pd
import numpy as np
from stellargraph.data import UniformRandomMetaPathWalk
from gensim.models import Word2Vec
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tqdm import tqdm





# concurrency
import concurrent.futures

## getting utils
import sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
import utils





# txt file for apps
def train_txt(malware, benign1, benign2, target):
    """
    benign_fp --> file path for directory of benign_apps
    mali_fp --> file path for directory of malicious apps

    Assigns an ID to each app

    output --> train.txt containing train apps, columns = app_ID, app_fp, label
    """

    benign_apps = [os.path.join(benign1, bee) for bee in os.listdir(benign1)] + \
    [os.path.join(benign2, bee) for bee in os.listdir(benign2)]
    benign_labels = [0] * len(benign_apps)
    print(len(benign_apps))

    # note, malware are already CFGs
    malware_apps = [os.path.join(malware, bee) for bee in os.listdir(malware)]
    malware_labels = [1] * len(malware_apps)
    print(len(malware_apps))

    apps = benign_apps + malware_apps
    labels = benign_labels + malware_labels

    # app ID's
    app_id = range(0, (len(benign_apps) + len(malware_apps)))

    csv = pd.DataFrame({
        "app_fp":apps,
        "app_label":labels,
        "app_ID":app_id
    })
    
    # build outputfp: 
    outfp = os.path.join(target, "app_label_id.txt")
    if os.path.exists(outfp) & (".txt" in outfp):
        os.remove(outfp)
    csv.to_csv(outfp, index = False)
    return csv







#     futures = []
#     with ThreadPoolExecutor(8) as executor:

#         for directory in directories:
#             filepaths = os.listdir(directory)
#             for filepath in filepaths:
#                 real_p = os.path.join(directory, filepath)
#                 now = datetime.now()
#                 futures.append(executor.submit(decompile_apk, real_p, target))
#         for job in as_completed(futures):
#             results = job.result()

def read_graph_process(fp):
    '''
    reads and decompresses .gml.bz2 file to obtain the graph
    
    fp --> filepath to .gml.bz2 file (should be the graph)
    '''
    # get app name
    direc, app = os.path.split(fp)
    app = app.replace(".gml.bz2", "")
    
    graph = nx.read_gml(fp)
#     graph.add_nodes_from([
#         app, {""}
#     ])
    
#     stellar = StellarGraph.from_networkx(graph, node_type_attr= 'type')
    return graph
#################################### API ABSTRACTION #############################################################
##################################################################################################################

        
def API_abstraction(kind, api):
    """
    Abstracts an API call
    
    kind --> What level of abstraction
    api --> the API call to abstract, an array of data
    """
    if type(api) != str:
        node, data = api
        if kind == "CLASS": # class level abstraction 
            # classes are formatted as Lclassname;
            # e.g., Ljava/lang/String;
            api_class = node.split()[0]
            return (api_class, data)
    else:
        api_class = api.split()[0]
        return api_class
    
def add_apk_node(G, appname): 
    """
    Adds the apk node to the graph, along with the various
    G --> the networkx graph object that we are adding app node to 
    appname --> the name of the app, if blank, it'll just add "apk"
    """
    
    if appname == "":
        G.add_nodes_from([("apk", {"type":"APK,Node"})])
        nx_nodes = np.array(G.nodes())
        edgesto = [("apk", node) for node in nx_nodes]
        edgesfrom = [(node, "apk") for node in nx_nodes]
        G.add_edges_from(edgesto)
        G.add_edges_from(edgesfrom)
    else:
        G.add_nodes_from([(appname, {"type":"%s,Node"%appname})])
        nx_nodes = np.array(G.nodes())
        edgesto = [(appname, node) for node in nx_nodes]
        edgesfrom = [(node, appname) for node in nx_nodes]
        G.add_edges_from(edgesto)
        G.add_edges_from(edgesfrom)
        
    return G
        
        
def edge_processing(kind, edge):
    """
    processes the edges so they are abstracted to some level
    returns a new edge (tuple) that is processed
    """
    
    api1, api2, weight = edge

    processed1, processed2 = API_abstraction(kind, api1), API_abstraction(kind, api2)
    return (processed1, processed2, weight)
    
        
def API_abstraction_vectorized(inFP, outFP, kind, to_return, truename = False):
    """
    abstracts edges and nodes of ONE APP to some level
    
    returns a graph that is abstracted (WILL CHANGE)
    
    inFP --> input file path (should be .gml.bz2)
    outFP --> output directory
    kind --> (str) FAMILY or PACKAGE or CLASS
    """
    
    # getting the app name
    direc, app_name = utils.dir_and_app(inFP)

    try:
        networkx = nx.read_gml(inFP)
    except:
        return inFP + " might be broken!"

    nx_nodes = np.array(networkx.nodes(data = True))
    nx_edges = np.array(networkx.edges, dtype = object)
    node_vfunc = np.vectorize(API_abstraction)
    edge_vfunc = np.vectorize(edge_processing)

    newnodes = [API_abstraction(kind, node) for node in nx_nodes]
    newedges = [edge_processing(kind, edge) for edge in nx_edges]

    G = nx.MultiDiGraph()
    G.add_nodes_from(newnodes)
    G.add_edges_from(newedges)
    if truename == False:
        G = add_apk_node(G, "")
    else:
        G = add_apk_node(G, app_name)
    metapaths = dfs(G, app_name)
        
    
    if to_return == "NX":
        return [G, metapaths]
    elif to_return == "SG":
        stellar = StellarGraph.from_networkx(G, node_type_attr = "type")
        return [stellar, metapaths]
##################################################################################################################
##################################################################################################################







        

###################################### OBTAINING METAPATHS #######################################################
##################################################################################################################

def dfs(G, appname):
    """
    performs dfs on a graph, outputs metapaths
    
    G --> networkx object
    appname --> name of the app (for apknode)
    """
    app_type = G.nodes[appname]['type']
    paths = []
    edges = list(nx.dfs_edges(G, appname))
    path = []
    for edge in edges:
        prev = ""
        for node in range(len(edge)):
            node_type = G.nodes[edge[node]]['type']
            if (node == 0) & (edge[node] == appname): # previous link has ended, new one has started
                path.append(app_type)
                paths.append(path)
                path = [app_type]
                prev = ""
            elif prev == node:
                continue
            elif prev != node:
                prev = node
                path.append(node_type)
                
    
    # filter paths
    to_ret = []
    for lst in paths:
        if len(lst)> 3:
            to_ret.append(lst)
    return to_ret


  
def metapath_builder_nodetype(node_types):
    """
    builds some metapaths using given nodetypes
    """
    node_types.remove("APK,Node")
    return [(["APK,Node"] + list(item) + ["APK,Node"]) for item in list(itertools.permutations(node_types))]

##################################################################################################################
##################################################################################################################





######################################  METAPATH2VEC #############################################################
##################################################################################################################
def metapath2vec(G, walk_length, metapaths):
    """
    performs metapath2vec and returns representations with labels
    
    G --> stellargraph object of the graph
    label --> (0 or 1) benign or not
    walk_length --> int, defines how long the sentences should be
    """
    rw = UniformRandomMetaPathWalk(G)
    walks =rw.run(
        nodes = list(G.nodes()),
        length = walk_length,
        n = 10,
        metapaths = metapaths
    )
    return walks
    

##################################################################################################################
##################################################################################################################




######################################  WORD2VEC and DOC2VEC #####################################################
##################################################################################################################
def unstack_walks(walkfp, appname):
    """
    unstacks the walks to obtain sentences
    """
    arr = np.loadtxt(walkfp, dtype = object)
    walks = []
    walk = []
    for element in arr:
        if element != appname:
            walk.append(element)
        elif element == appname:
            walks.append(walk)
            walk = []
            walk.append(element)
            
    return walks[1:]


def word2vec(walks):
    """
    performs word2vec on walks on the common graph
    
    walks --> directory of the walks
    """
    model = Word2Vec(walks, size=128, window=5, min_count=0, sg=1, workers=4, iter=1)
    return model.wv

def doc2vec_train(train, path_to_walks, app_id_fp):
    """
    performs doc2vec on the walks to obtain document vectors
    USE ON SEPARATE APKs
    
    path_to_walks --> directory conatining the metapath2vec walks
    """
    documents = []
    labels = []
    df = pd.read_csv(app_id_fp)
    
    train = [utils.dir_and_app(app)[1] for app in train]
    paths = [os.path.join(path_to_walks, (appname + "m2v_walks.txt")) for appname in train]
    
    for walk in tqdm(range(len(paths))):
        try:
            documents.append(np.loadtxt(paths[walk], dtype = object))
            direc, appname = utils.dir_and_app(paths[walk])
            label = df[df.app_fp.str.contains(appname)].app_label.iloc[0]
            labels.append(label)
            
        except:
            print("app ", paths[walk], " is broken")
        
    
    docs = [TaggedDocument(doc, [i]) for i, doc in enumerate(documents)]
    documents = []
    
    
    model = Doc2Vec(docs, vector_size=100, window=300, min_count=1, workers=4)
    
    return [model, labels]

def doc2vec_test(test, path_to_walks, app_id_fp, model, target, metapathsFP, walksFP):
    """
    infers test item for unseen apps
    
    test --> list of test app names
    path_to_walks --> the path to the walks of apps
    app_id_fp --> filepath of information
    model --> the trained model
    """
#     model = Doc2Vec.load(model_fp)

    
    documents = []
     # assume that the data is coming from the apps that we have
    labels = []
    df = pd.read_csv(app_id_fp)
    if ".gml.bz2" in test[0]:
        app_names = [utils.dir_and_app(app)[1] for app in test]
    else:
        app_names = test
    paths = [os.path.join(path_to_walks, (appname + "m2v_walks.txt")) for appname in app_names]
    for ind in range(len(paths)):
        walk = paths[ind]

#         if not(os.path.exists(walk)): # if this app has not been traversed yet
#             # find the app location, and create files for it
#             wrapper(test[ind], target, metapathsFP, walksFP)
        if os.path.exists(walk):
            documents.append(np.loadtxt(walk, dtype = object))
            direc, appname = utils.dir_and_app(walk)
            label = df[df.app_fp.str.contains(appname)].app_label.iloc[0]
            labels.append(label)

        
    X = []
    for test_app in documents:
        X.append(model.infer_vector(test_app))
        
    return [X, labels]


            
    


##################################################################################################################
##################################################################################################################





######################################  WRAPPERS AND EMBEDDINGS ##################################################
##################################################################################################################

            
def wrapper(apk, target, metapathsFP, walksFP):
    """
    wrapper to build features for doc2vec, metapath2vec. 
    
    apk --> filepath to the apk
    target --> filepath to store common graph txts (for metapath2vec)
    metapathsFP --> filepath to store metapath2vec txts (for metapath2vec)
    walksFP --> filepath to store metapths2vec walks txt (for doc2vec)
    
    """
    if ".gml.bz2" in apk:
        direc, appname = utils.dir_and_app(apk)
    else:
        appname = apk
    
    document_out = os.path.join(walksFP, (appname + "m2v_walks.txt"))
    metapath_out = os.path.join(metapathsFP, (appname + "m2v_metapaths.txt"))
    graph_out = os.path.join(target, (appname + "graph.txt"))
    
    if (os.path.exists(document_out)) & (os.path.exists(metapath_out)) & (os.path.exists(graph_out)):
        print("the app: ", apk, " is already done!")
    else:
        try:
            networkx, metapaths = API_abstraction_vectorized(apk, "", "CLASS", "NX", True)
            stellar = StellarGraph.from_networkx(networkx, node_type_attr = "type")
            ################## COMMON GRAPH INFORMATION ##################
            if not os.path.exists(graph_out):
                with open(graph_out, 'a') as file: 
                    for edge in np.array(networkx.edges):
                        node1, node2, weight = edge
                        type1 = networkx.nodes[node1]["type"]
                        type2 = networkx.nodes[node2]["type"]

                        # columns are: ["node1", "node2", "weight", "type1", "type2"]
                        row = " ".join([node1, node2, weight, type1, type2]) + "\n"

                        file.write(row)
                file.close()
            ##############################################################


            ################## DOC2VEC AND METAPATH2VEC INFORMATION ##################
            try:
                # OUTPUT WALKS OF ONE APP
                if not os.path.exists(document_out):
                    document = metapath2vec(stellar, 500, metapaths)
                    np.savetxt(document_out, np.hstack(document), fmt = "%s")

                # OUTPUT METAPATHS OF ONE APP
                if not os.path.exists(metapath_out):
                    joined = ["->".join(lst) for lst in metapaths]
                    np.savetxt(metapath_out, joined, fmt = "%s")
                print("the app: ", apk, " has finished!")
            except:
                print("The app: ", apk, " seems to be broken!")
                
        except:
            print("The app: ", apk, " seems to be broken!")
        
            

    
##################################################################################################################
##################################################################################################################

#################################### BUILDING EMBEDDINGS ##################################################################################################################
def building_embeddings(app_ids_fp, metapathsFP, walksFP):
    """
    builds the embeddings of each app
    
    app_ids_fp --> filepath to each of the apps
    metapathsFP --> path to where metapaths are stored
    walksFP --> path to where the walks are stored
    """
    df = pd.read_csv(app_ids_fp)
    
    walks = []

    for row in tqdm(range(len(df))):
        app_fp = df.iloc[row]["app_fp"]
        app_label = df.iloc[row]["app_label"]
        directory, app_name = utils.dir_and_app(app_fp)
        
        metapath_fp = os.path.join(metapathsFP, (app_name+"m2v_metapaths.txt"))
        walk_fp = os.path.join(walksFP, (app_name + "m2v_walks.txt"))
        if os.path.exists(walk_fp) & os.path.exists(metapath_fp):
            walk = unstack_walks(walk_fp, app_name)
            walks = walks + walk

    return walks





##################################################################################################################





if __name__ == "__main__":

    # ur username: change here
    USER = "edh021"


    # target
    target = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/actualdroid_intermediate_files/metapath2vec_outputs" 
    malware = "/teams/DSC180A_FA20_A00/a04malware/apks/malware"
    popular = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/benign_graphs_sab/popular_apks"
    random = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/benign_graphs_sab/random_apps"

    malware_apks = [os.path.join(malware, item) for item in os.listdir(malware)]
    popular_apks = [os.path.join(popular, item) for item in os.listdir(popular)]
    random_apks = [os.path.join(random, item) for item in os.listdir(random)]
    
    #for common graph
    apks = malware_apks + popular_apks + random_apks
    metapathsFP = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/actualdroid_intermediate_files/metapath2vec_metapaths"
    walksFP = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/actualdroid_intermediate_files/metapath2vec_walks"
    commongraphFP = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/common_graph"
    
#     compose_out = os.path.join(commongraphFP, "commongraph.gml.bz2")
#     compose = nx.compose_all(results)
#     nx.write_gml(compose, compose_out)



        

        

    print("Done")
