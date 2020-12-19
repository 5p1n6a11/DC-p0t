#!/usr/bin/bash -eu

python3 setup/create_dockerfile.py
docker image build -t dc-p0t/victim_con:1 .
docker run -it -d -p 8080:80 --name victim dc-p0t/victim_con:1
docker exec victim hostname -i
