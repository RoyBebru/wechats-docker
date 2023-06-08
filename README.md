# wechats-docker

Simple chat via python ThreadedHTTPServer()

Installation:

    docker pull roybebru/wechats-docker

Run in background:

    docker run -p 3000:3000 -v ./storage:/app/storage -d roybebru/wechats-docker

Run in with debug output in terminal (foreground):

    docker run -p 3000:3000 -v ./storage:/app/storage    roybebru/wechats-docker

Build image:

    docker build . -t roybebru/wechats-docker
