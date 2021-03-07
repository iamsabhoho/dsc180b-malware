import os
import numpy as np
import pandas as pd
from tqdm import tqdm
from stellargraph import StellarGraph
from stellargraph import IndexedArray
from stellargraph.data import UniformRandomMetaPathWalk
from gensim.models import Word2Vec
from datetime import datetime



import sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
import utils
from data import data_androguard as da


def get_commongraph(common_graph_txts, train, subset = False):
    """
    gets the large dataframe of edges
    common_graph_txts --> path to the directory of common graph edges
    train_apps --> list of filepaths to the edges txt
    """
    now = datetime.now()
    apps = [os.path.join(common_graph_txts, (appname + "graph.txt")) for appname in train]
    if subset == True:
        apps = apps[:10]
    lst_of_dfs = []
    
    for app in apps:
        if os.path.exists(app):
            df = pd.read_csv(app, delimiter = " ", header = None)
            lst_of_dfs.append(df)

    concat = pd.concat(lst_of_dfs, ignore_index = True)
    
    concat.columns = ["source", "target", "weight", "type1", "type2"]
    concat.type1 = concat.type1.apply(fix_node_type)
    concat.type2 = concat.type2.apply(fix_node_type)
    
    no_dup = concat.drop_duplicates(subset = "source", keep = "last")
    dct = no_dup.groupby(['type1'])['source'].apply(lambda grp: list(grp.value_counts().index)).to_dict()
    
    for key in dct.keys():
        dct[key] = IndexedArray(index = dct[key])
    
    commongraph = StellarGraph(dct, concat[["source", "target", "weight"]])
    print("common graph loaded: ", (datetime.now() - now))
    return commongraph

def common_metapath2vec(metapaths, commongraph, root_nodes, walk_length):
    """
    from the filepath, returned a combined list of all metapaths
    
    metapathsFP --> filepath to the directory containing all metapaths
                    should be: "/teams/DSC180A_FA20_A00/a04malware/personal-group03/actualdroid_intermediate_files/metapath2vec_metapaths"
                    
    common_graph_txts --> path to a folder containing elements of the common graph
                    should be: "/teams/DSC180A_FA20_A00/a04malware/personal-group03/common_graph/common_graph_txts"
    """
    
    # start traversal
    walk_length = 100
    rw = UniformRandomMetaPathWalk(commongraph)
    walks = rw.run(
        nodes=root_nodes,  # root nodes
        length=walk_length,  # maximum length of a random walk
        n=1,  # number of random walks per root node
        metapaths=metapaths,  # the metapaths
    )
    print("Number of random walks: {}".format(len(walks)))
    
    return walks


    
    
def build_dict_nodetypes(df, dct, visited):
    """
    builds a dictionary of {node type:[nodes]}, from two arrays
    """
    type1 = set(list(df.type1))
    for kind in type1:
        nodes_of = set(list(edge[edge.type1 == kind].source))
        new_nodes = nodes_of - visited

        if kind in dct:
            new_index = list(dct[kind].index) + list(new_nodes)
            
            dct[kind] = pd.DataFrame(index = new_index)

        elif kind not in dct:
            dct[kind] = pd.DataFrame(index = nodes_of)
            
        visited.update(new_nodes)
            
            
            
    for key in dct.keys():
        index = list(dct[key].index)
        dct[key] = pd.DataFrame(index = list(set(index)))
    return dct, visited

def list_to_line(lst):
    """
    turns a list of items into a long string to write
    """
    lst = [str(i) for i in lst]
    return "".join(np.array(lst, dtype = object) + "\n")

def fix_node_type(node):
    """
    fixes some node types
    """
    
    if node == "Node":
        return node
    elif ",Node" not in node:
        node = node.replace("Node", ",Node")
        return node
    else:
        return node
    
def full_metapaths(metapathsFP):
    """
    returns all metapaths if necessary
    
    metapathsFP --> path to where metapaths are stored
    """
    now = datetime.now()
    # all metapaths
    metapaths_fps = utils.list_files(metapathsFP)
    metapaths = []

    for mp in metapaths_fps:
        try:
            metapath = np.loadtxt(mp, dtype = object)
            metapath = [[fix_node_type(node) for node in lst.split("->")] for lst in metapath]

            metapaths = metapaths + metapath
        except:
            continue
            
    print("full metapaths built in: ", (datetime.now() - now))
    return metapaths

    
def reduced_metapaths(metapathsFP):
    """
    returns reduced amounts of metapaths, to ease computation
    
    metapathsFP --> path to where metapaths are stored
    """
    # reduced metapaths
    now = datetime.now()
    metapaths_fps = utils.list_files(metapathsFP)
    reduced_metapaths = []

    for mp in metapaths_fps:
        try:
            metapath = np.loadtxt(mp, dtype = object)
            metapath = [[fix_node_type(node) for node in lst.split("->")] for lst in metapath]

            reduced_metapaths = reduced_metapaths + list(np.random.choice(metapath, 3))
        except:
            continue
    print("reduced metapaths built in: ", (datetime.now() - now))
    
    return reduced_metapaths


def root_nodes(commongraph, metapaths, ids = False):
    """
    get root nodes for node embedding learning, returns as 
    
    
    """
    # getting unique nodes, getting root nodes, from metapaths
    unique_nodes = []
    for path in metapaths:
        unique_nodes.append(path[0].replace(",Node", ""))
    len(set(unique_nodes))
    unique_nodes = list(set(unique_nodes))
    
    
    indices = commongraph.node_ids_to_ilocs(list(commongraph.nodes()))
    all_nodes = list(commongraph.nodes())

    unique_indices = []
    for item in tqdm(indices):
        node = all_nodes[item]
        if node in unique_nodes:
            unique_indices.append(item)
            
    return [unique_nodes, unique_indices]

    
def run(graph, nodes, metapaths, n=1, length=100):
    """
    Performs metapath-driven uniform random walks on heterogeneous graphs.
    taken from stellargraph's metapath2vec source code: https://stellargraph.readthedocs.io/en/stable/_modules/stellargraph/data/explorer.html#UniformRandomMetaPathWalk


    Returns:
        List of lists of nodes ids for each of the random walks generated
    """
#     nodes = graph.node_ids_to_ilocs(nodes)

    walks = []
    print("number of nodes: ", len(nodes))
    for ind in range(len(nodes)):
        node = nodes[ind]
        print("Working on: ", ind, " now!")
        # retrieve node type
        label = graph.node_type(node, use_ilocs=True)
        filtered_metapaths = [metapath for metapath in metapaths if len(metapath) > 0 and metapath[0] == label]

        for metapath in filtered_metapaths:
            # augment metapath to be length long
            # if (
            #     len(metapath) == 1
            # ):  # special case for random walks like in a homogeneous graphs
            #     metapath = metapath * length
            # else:
            metapath = metapath[1:] * ((length // (len(metapath) - 1)) + 1)
            for _ in range(n):
                walk = ([])  # holds the walk data for this walk; first node is the starting node
                current_node = node
                for d in range(length):
                    walk.append(current_node)
                    # d+1 can also be used to index metapath to retrieve the node type for the next step in the walk
                    neighbours = graph.neighbor_arrays(current_node, use_ilocs=True)
                    # filter these by node type
                    neighbour_types = graph.node_type(neighbours, use_ilocs=True)
                    neighbours = [neigh for neigh, neigh_type in zip(neighbours, neighbour_types) if neigh_type == metapath[d]]

                    if len(neighbours) == 0:
                        # if no neighbours of the required type as dictated by the metapath exist, then stop.
                        break
                    # select one of the neighbours uniformly at random
                    current_node = np.random.choice(neighbours)
                        # the next node in the walk

                walks.append(
                    list(graph.node_ilocs_to_ids(walk))
                )  # store the walKS
    return walks

def build_embedding(app_name, walksFP, w2vmodel):
    """
    builds an embedding vector for an app
    """
    feature_size = w2vmodel.wv.vectors.shape[1]
    feature_vector = [0] * feature_size
    
    walks_file = os.path.join(walksFP, (app_name + "m2v_walks.txt"))
    nodes = []
    try:
        with open(walks_file, 'r') as file:
            for line in file:
                nodes.append(line.strip())
        file.close()
    except:
        return feature_vector
    
    
    nodes = set(nodes)
    for node in nodes:
        # do some operation based on the api's inside that app, can change! 
        try:
            vec = w2vmodel.wv.get_vector(node)
            feature_vector = feature_vector + vec
        except:
            continue
        
    return feature_vector
    
    
    
    

def metapath2vec(commonFP, train_apps, metapathFP, app_ids_fp, walksFP, mdl_fp, walk_length = 100, reduced = False, subset = False, testing = False):
    """
    wrapper function
    performs metapath2vec on the commongraph
    outputs: X and y
    
    commonFP --> filepath to the directory containing txts for common graph 
            txts columns are --> ["node1", "node2", "weight", "type1", "type2"]
            
    metapathFP --> filepath to the directory of metapaths of separate apps (from doc2vec)
    app_ids_fp --> filepath to the csv containing app and label information
    walksFP --> filepath too the directory of walks of separate apps (from doc2vec)
    
    """
    df = pd.read_csv(app_ids_fp)
    if testing == True:
        train_apps = [utils.dir_and_app(item)[1] for item in train_apps]
        


    # get the common graph
    commongraph = get_commongraph(commonFP, train_apps, subset)

    # get the metapaths
    if reduced == True:
        metapaths = reduced_metapaths(metapathFP)
    elif reduced == False:
        metapaths = full_metapaths(metapathFP)

    
    # get root nodes as indices
    nodes, indices = root_nodes(commongraph, metapaths)

    
    # run metapath2vec
    walks = run(commongraph, indices, metapaths)

    if os.path.exists(mdl_fp):
        print("model already exists, will load it in .....")
        model = Word2Vec.load(mdl_fp)
    else:
        # gensim word2vec
        model = Word2Vec(walks, size=128, window=5, min_count=0, sg=1, workers=2, iter=1)
        model.save(mdl_fp)
    
    X = []
    y = []

    for node in nodes:
        X.append(build_embedding(node, walksFP, model))
        try:
            y.append(df[df.app_fp.str.contains(node)].app_label.iloc[0])
        except:
            y.append(0)

    
    
    return [X, y]

def metapath2vec_testing(commonFP, modelFP, walksFP, metapathsFP, test, app_ids_fp, labels = None):
    """
    testing on metapaths
    
    """
    df = pd.read_csv(app_ids_fp)
    
    X = []
    labels = []
        
    model = Word2Vec.load(modelFP)
    walks = [os.path.join(walksFP, (appname + "m2v_walks.txt")) for appname in test]
    
    for ind in range(len(walks)):
        walk = walks[ind]
#         if not os.path.exists(walk):  ## if the app hasn't been preprocessed before
#             da.wrapper(test[ind], commonFP, metapathsFP, walksFP)
        if os.path.exists(walk):
            # get this app's embedding
            X.append(build_embedding(test[ind], walksFP, model))
            labels.append(df[df.app_fp.str.contains(test[ind])].app_label.iloc[0])
        
            
    return [X, labels]
    
    
    
    
    
    

if __name__ == "__main__":
    
    
            
    walk_length = 100
    # rw = UniformRandomMetaPathWalk(commongraph)
    walks = run(
        graph = commongraph,
        nodes= unique_indices,# root nodes
        length=walk_length,  # maximum length of a random walk
        n=1,  # number of random walks per root node
        metapaths=reduced_metapaths,  # the metapaths
    )

    print("Number of random walks: {}".format(len(walks)))