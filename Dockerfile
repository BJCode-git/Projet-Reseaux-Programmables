FROM registry.app.unistra.fr/jr.luttringer/reseaux-programmables-conteneur/p4-utils

COPY requirements.txt /home/requirements.txt

RUN pip3 install -r /home/requirements.txt


