#!/usr/bin/bash -eu

python3 setup/create_dockerfile.py
sudo docker image build -t dc-p0t/victim_con:1 .
sudo docker run -it -d -p 8080:80 --name victim dc-p0t/victim_con:1
sudo docker exec victim hostname -i
