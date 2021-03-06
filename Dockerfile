FROM arg-tech/ws:python-0.1

MAINTAINER m.snaith@dundee.ac.uk

# Get the necessary binaries
RUN apk add git
RUN pip3 install --upgrade pip

ADD ./src /app
ADD requirements.txt /
RUN pip3 install -r /requirements.txt

WORKDIR /app

ENV MONGO dgep_mongo_test

ENV APP_NAME dgep
ENV VERSION 1.0.1
ENV HOST localhost:8888
