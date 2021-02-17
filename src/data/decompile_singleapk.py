from androguard import misc
from stellargraph import StellarGraph
import sys, os
import numpy as np
import sys

import networkx as nx

from datetime import datetime

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

def features_encoder(node_data):
    """
    encoding the feature dictionary from .get_call_graph() from Androguard
    """
    keywords= ["external", 'entrypoint', 'native', 'public', 'static'] #'vm', 'codesize']
    vector = []
    for keyword in keywords:
        try:
            if node_data[keyword] == True:
                vector.append(1)
            else:
                vector.append(0)

        except:
            vector.append(0)

    return vector

def features_encoder2(node_data):
    '''
    gets the node type for an individual node
    '''
    keywords= ["external", 'entrypoint', 'native', 'public', 'static']

    string = ""
    for keyword in keywords:
        if node_data[keyword] == True:
            string += (keyword + ",")

    string += "Node"
    return string



def decompile_apk(filepath):
    '''
    decompiles an apk and outputs a gml file of the graph. Will write to disk.

    filepath --> path to the APK file
    session_n --> session filename, extension is '.ag'


    '''
    current_dir = os.getcwd()
    target_dir = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/benign_graphs"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # build fp
    path, app = os.path.split(filepath)
    app = app.replace(".apk", "")

    final_path = os.path.join(target_dir, (app + ".gml.bz2"))


    a, d, dx = misc.AnalyzeAPK(filepath)
    networkx_graph = dx.get_call_graph()

    mapping = {}
    for node_id, node_data in networkx_graph.nodes(data = True):
        mapping[node_id] = str(node_id.get_method().full_name)
        node_data['feature'] = features_encoder(node_data)
        node_data['type'] = features_encoder2(node_data)

    G = nx.relabel_nodes(networkx_graph, mapping)
    nx.write_gml(G, final_path)
   

    return app

if __name__ == "__main__":
    now = datetime.now()
    
    directories = ["/teams/DSC180A_FA20_A00/a04malware/apks/random-apps", "/teams/DSC180A_FA20_A00/a04malware/apks/popular_apks"]
    for directory in directories:
        print(directory, " exists?? ", os.path.exists(directory))
    
    
    futures = {}

    with ThreadPoolExecutor() as executor:
        for directory in directories:
            filepaths = os.listdir(directory)
            for filepath in filepaths:
                real_p = os.path.join(directory, filepath)
                
                
                futures[executor.submit(decompile_apk, real_p)] = real_p
                app_names.append(real_p)

        for job in as_completed(futures):
            path = futures[job]
            try:
                results = job.result()

            except:
                print(path, " went wrong")
            else:
                print(path, " completed")

            

    print("Time taken: ", (datetime.now() - now))
    
