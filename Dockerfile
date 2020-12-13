# USAGE EXAMPLES
# docker build -t insider .
# docker run -ti --rm -v $(pwd)/project:/opt/insider insider -tech android -target /opt/insider
# docker run -ti --rm -v $(pwd)/project:/opt/insider insider -tech javascript -target </opt/insider>
# docker run -ti --rm -v $(pwd)/project:/opt/insider insider -tech=android -target=</opt/insider>
# docker run -ti --rm -v $(pwd)/project:/opt/insider insider -tech android -target </opt/insider> -no-html

FROM alpine
ENV VERSION 2.0.5
RUN mkdir -p /opt/insider
WORKDIR /opt/insider
RUN wget -q -O - "https://github.com/insidersec/insider/releases/download/${VERSION}/insider_${VERSION}_linux_x86_64.tar.gz" | tar xz
RUN chmod +x insider
ENTRYPOINT [ "./insider" ]
CMD [ "--help" ]
