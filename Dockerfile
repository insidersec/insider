# USAGE EXAMPLES
# docker build -t insider .
# docker run -ti --rm insider -tech android -target $pwd
# docker run -ti --rm insider -tech javascript -target <myprojectfolder>
# docker run -ti --rm insider -tech=android -target=<myandroidfolder>
# docker run -ti --rm insider -tech android -target <myfolder> -no-html

FROM  alpine

    ENV VERSION 2.0.5
    RUN wget -q -O - "https://github.com/insidersec/insider/releases/download/${VERSION}/insider_${VERSION}_linux_x86_64.tar.gz" | tar xz
    RUN chmod +x insider
    ENTRYPOINT [ "./insider" ]
    CMD [ "--help" ]
