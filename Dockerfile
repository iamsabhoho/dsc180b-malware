# 1) choose base container
# generally use the most recent tag

# data science notebook
# https://hub.docker.com/repository/docker/ucsdets/datascience-notebook/tags
FROM ucsdets/datascience-notebook:2020.2-stable
# scipy/machine learning (tensorflow)
# https://hub.docker.com/repository/docker/ucsdets/scipy-ml-notebook/tags
# ARG BASE_CONTAINER=ucsdets/scipy-ml-notebook:2020.2-stable



# 2) change to root to install packages
USER root

RUN	apt-get install -y aria2 \
					   nmap \
					   traceroute
# 3) install packages
RUN pip install --no-cache-dir networkx scipy python-louvain numpy scikit-learn tqdm androguard
	
# 4) change back to notebook user
COPY /run_jupyter.sh /
RUN chmod 755 /run_jupyter.sh
USER $NB_UID
