# DGEP Web Service

The DGEP Web Service provides a RESTful deployment of the Dialogue Game Execution Platform (https://github.com/arg-tech/dgep).

## Prerequisites

1. Docker (https://www.docker.com)
2. ARG-tech Web Services docker image (https://github.com/arg-tech/ws)

## Getting started

1. Clone this repository
2. Edit the Dockerfile and docker-compose.yml files to suit your environment (e.g. ports)
3. Run `docker-compose up` to start the web service
4. Visit http://localhost:8888/dgep (changing 8888 if you changed the port in step 2)

## Usage

Some of the methods require authentication. To authenticate:

1. Create a new user via the `/auth/register` method
2. Login using the user credential via the `/auth/login` method
3. Copy the returned auth token
4. Click "Authorize"
5. Paste the auth token into the box; click "Authorize"

Full documentation for DGEP will be available on the DGEP library github page: https://github.com/arg-tech/dgep

Note that the web services uses a specific stable commit of dgep. You can use a more up-to-date version by editing requirements.txt with the appropriate commit hash.
