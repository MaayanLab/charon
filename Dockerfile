FROM ubuntu:22.04

LABEL maintainer="Alexander Lachmann <alexander.lachmann@mssm.edu>"

RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    python3-setuptools \
    libmysqlclient-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config
    
RUN pip3 install --upgrade pip 
RUN pip3 install --upgrade pip setuptools
RUN pip3 install tornado
RUN pip3 install pymysql
RUN pip3 install mysqlclient
RUN pip3 install requests
RUN pip3 install python-dateutil
RUN pip3 install boto3
RUN pip3 install python-dotenv

RUN rm -rf /var/lib/apt/lists/* # Clean up to reduce image size

WORKDIR /usr/local/src
RUN mkdir -p /app/tornado/data
COPY . /app/tornado

EXPOSE 5000

WORKDIR /app/tornado

RUN groupadd -r myappgroup && useradd -r -g myappgroup myappuser
USER myappuser

RUN python3 --version

ENTRYPOINT ["python3", "maintornado.py"]