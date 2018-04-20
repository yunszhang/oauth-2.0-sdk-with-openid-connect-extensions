# Docker File for Connect2id-server.zip
# Must be executed from a folder where Connect2id-server.zip is unzipped

FROM openjdk:8-jre

WORKDIR /c2id-server

ADD . /c2id-server

EXPOSE 8080

# path relative to /c2id-server
CMD ["bash", "tomcat/bin/startup.sh fg"]
