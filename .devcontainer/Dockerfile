FROM golang:latest

ARG DEVUSER devuser
ARG DEVUID 1000

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
 && apt-get -y install --no-install-recommends build-essential \
    g++ gdb doxygen git openssh-client openssl libssl-dev wget vim sudo \
    python3 python3-dev python3-pip \
 && python3 -m pip install cookiecutter sphinx breathe sphinx_rtd_theme
RUN apt-get -y install --no-install-recommends golang-go # TODO: Finish this

ENV DEVUSER=${DEVUSER}
RUN adduser --uid ${DEVUID} --disabled-password --gecos "" ${DEVUSER} \
    && echo "${DEVUSER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${DEVUSER} \
    && groupadd docker && usermod -aG docker ${DEVUSER} && newgrp docker

RUN apt-get -y update \
    && apt-get -y install openssh-client openssl libssl-dev wget vim \
    && apt-get -y install ca-certificates curl gnupg lsb-release acl \
    && apt-get -y remove docker docker.io containerd runc \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get -y update \
    && apt-get -y install docker-ce-cli docker-compose-plugin

USER ${DEVUSER}
CMD sudo setfacl -m "g:docker:rw" /var/run/docker.sock
RUN echo >>/home/${DEVUSER}/.profile && echo "sudo setfacl -m \"g:docker:rw\" /var/run/docker.sock" >>/home/${DEVUSER}/.profile

