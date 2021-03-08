import os
import ast
import numpy as np
import pandas as pd
import networkx as nx
from tqdm import tqdm
import matplotlib.pyplot as plt
from collections import Counter
from stellargraph import StellarGraph


def eda(graph):
    '''
    eda for an apk

    graph --> filepath to a graph
    returns a dictionary in case
    '''

    app_dir, app_filename = os.path.split(graph)
    
    #building output
    target = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/eda_sab/features1/"
    out_csv = os.path.join(target, (app_filename + ".csv"))
    target1 = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/eda/features/"
    others = os.path.join(target1, (app_filename + ".csv"))

    if os.path.exists(out_csv):
        print("csv exists already")
        return "csv exists already"
    if os.path.exists(others):
        print("csv others exists already")
        return "csv others exists already"

    try:
        networkx = nx.read_gml(graph)
    except:
        return graph + " might be broken!"

    stellar = StellarGraph.from_networkx(networkx, node_type_attr = "type")

    nodes = stellar.node_types
    node_types = {}
    for node in nodes:
        node_types[node] = len(stellar.nodes_of_type(node_type=node))

    data = {}
    
    # get number of nodes and edges
    data["app"] = graph
    data["node_types_counts"] = len(stellar.node_types)
    data["node_types"] = node_types
    data["number_nodes"] = len(stellar.nodes())
    data["number_edges"] = len(stellar.edges())

    if "benign" in app_dir:
        label = 0
    else:
        label = 1

    data["label"] = label
    
    df = pd.DataFrame.from_dict([data])
    
    return df.to_csv(out_csv)


def eda_plot():
    """
    plot the eda data

    """

    df1 = pd.read_csv('eda_malware.csv')
    df2 = pd.read_csv('eda_random.csv')
    df3 = pd.read_csv('eda_popular.csv')

    df = pd.concat([df1, df2, df3], ignore_index=True)
    df['label'].replace([0,1],['Benign','Malware'],inplace=True)

    colors = ['#EAB6AB','#D9E6F3','#CBAACB','#CCE2CB', '#FFAEA5', '#A2E1DB', '#97C1A9']
    # b vs. m: node types counts
    f1 = pd.crosstab(df['label'], df['node_types_counts'])

    f1 = pd.DataFrame({"3 Types": [1, 4], "4 Types": [1, 407], "5 Types": [245, 5768], "6 Types": [39, 1113], "7 Types": [83, 487], "8 Types": [154, 368], "9 Types": [103, 286]}).rename(index={0:'Benign', 1:'Malware'})
    f1.plot(kind='bar', color=colors)
    fig = plt.gcf()
    plt.legend(loc='upper left')
    plt.title('Benign vs. Malicious: Number of Node Types')
    fig.savefig('bv_node_types.png')

    # for a better look, limit type 5 malware to 2k counts only
    f1 = pd.DataFrame({"3 Types": [1, 4], "4 Types": [1, 407], "5 Types": [245, 2000], "6 Types": [39, 1113], "7 Types": [83, 487], "8 Types": [154, 368], "9 Types": [103, 286]}).rename(index={0:'Benign', 1:'Malware'})
    f1.plot(kind='bar', color=colors)
    fig = plt.gcf()
    plt.legend(loc='upper left')
    plt.title('Benign vs. Malicious: Number of Node Types')
    fig.savefig('bv_node_types1.png')

    # node types
    # for malware: extract node types info for node types counts > 5, and sum up each types counts
    node_types = df[(df['label'] == 'Malware') & (df['node_types_counts'] >= 5)]['node_types'] #series
    lst = [ast.literal_eval(s) for s in node_types]

    c = Counter()
    for d in lst:
        c.update(d)

    df_nt = pd.DataFrame(dict(c).items(), columns=['node_types', 'counts'])
    df_nt = df_nt.sort_values(by=['counts'])

    sizes = [215060, 2823059, 3135725, 5641356, 10679709, 16547701]
    labels = ['Others', 'static,Node', 'public,static,Node', 'Node', 'external,Node', 'public,Node']

    colors = ['#EAB6AB','#D9E6F3','#CBAACB','#CCE2CB', '#FFAEA5', '#A2E1DB']

    fig1, ax1 = plt.subplots(figsize=(7, 7))
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
            shadow=False, startangle=90, colors=colors)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Malware: Top Node Types and Its Counts', y=1.05)

    plt.show()
    fig1.savefig('counts_pie_m.png')

    # for benign: extract node types info for node types counts, and sum up each types counts
    node_types = df[(df['label'] == 'Benign')]['node_types'] #series
    lst = [ast.literal_eval(s) for s in node_types]

    c = Counter()
    for d in lst:
        c.update(d)

    df_nt = pd.DataFrame(dict(c).items(), columns=['node_types', 'counts'])
    df_nt = df_nt.sort_values(by=['counts'])

    sizes = [77967, 2892033, 2964924, 5287258, 6478196, 20364339]
    labels = ['Others', 'staticNode', 'public,staticNode', 'external,Node', 'Node', 'public,Node']

    colors = ['#EAB6AB','#D9E6F3','#CBAACB','#CCE2CB', '#FFAEA5', '#A2E1DB']

    fig1, ax1 = plt.subplots(figsize=(7, 7))
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
            shadow=False, startangle=90, colors=colors)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Benign: Top Node Types and Its Counts', y=1.05)

    plt.show()
    fig1.savefig('counts_pie_b.png')

    # benign vs malware: counts
    sizes = [8435, 802]
    labels = ['Benign', 'Malware']

    colors = ['#EAB6AB','#D9E6F3']

    fig1, ax1 = plt.subplots(figsize=(7, 7))
    ax1.pie(sizes, labels=labels, autopct='%1.1f%%',
            shadow=False, startangle=90, colors=colors)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Number of Benign vs. Malware', y=1.05)

    plt.show()
    fig1.savefig('bm_counts.png')

    # number of edges vs number of nodes
    groups = df.groupby('label')
    colors = ['#FFAEA5', '#A2E1DB']

    # Plot
    fig, ax = plt.subplots()
    ax.margins(0.05) # Optional, just adds 5% padding to the autoscaling
    for name, group in groups:
        if name == 'Benign':
            c = colors[0]
        else:
            c = colors[1]
        ax.plot(group.number_edges, group.number_nodes, marker='o', linestyle='', ms=4, label=name, c=c)
    ax.legend()
    ax.set_xlabel('Number of Edges')
    ax.set_ylabel('Number of Nodes')
    ax.set_title('Benign & Malware: Number of Edges vs. Number of Nodes', y=1.05)

    plt.show()
    fig.savefig('bm_edges_nodes.png')


if __name__ == "__main__":

    # popular
    benign1_directory = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/benign_graphs_sab/popular_apks/"

    # random
    benign2_directory = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/benign_graphs_sab/random_apps/"
    
    # malware
    malware_directory = "/teams/DSC180A_FA20_A00/a04malware/apks/malware/"

    # get csv
    
    target = benign1_directory
    fps = os.listdir(target)
    print("LEN OF FPS: ", len(fps))

    for i in tqdm(range(len(fps))):
        fp = fps[i]
        if ".bz2" in fp:
            built = os.path.join(target, fp)
            d = eda(built)
    
    print("EDA START COMBINING")
    # combine csv
    target = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/eda_sab/features1/"
    target1 = "/teams/DSC180A_FA20_A00/a04malware/personal-group03/eda/features/"
    fps1 = os.listdir(target)
    fps2 = os.listdir(target1)

    fps11 = [os.path.join(target, i) for i in fps1]
    fps22 = [os.path.join(target1, i) for i in fps2]

    fps = fps11 + fps22

    columns = ["app", "node_types_counts", "node_types", "number_nodes", "number_edges", "label"]
    df = pd.DataFrame(columns = columns)

    for i in tqdm(range(len(fps))):
        fp = fps[i]
        if ".csv" in fp:
            built = os.path.join(target, fp)
            d = pd.read_csv(built)
            df = df.append(d, ignore_index=True)
        
    df.to_csv("/teams/DSC180A_FA20_A00/a04malware/personal-group03/eda_sab/eda_popular.csv")
    print("EDA POPULAR ALL DONE")
        
        
