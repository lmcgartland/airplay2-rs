FROM rust:1.60-buster

WORKDIR /usr/src/airplay2-rs
COPY . .

RUN apt-get update
# Install Linux dependencies
RUN apt install xorg-dev libxcb-shape0-dev libxcb-xfixes0-dev libavahi-client-dev clang -y
# This daemon will need to be running at run-time.
RUN apt-get install avahi-daemon -y

RUN cargo build

CMD ["/bin/bash"]