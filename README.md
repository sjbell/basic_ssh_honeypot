# Basic SSH Honeypot
A basic SSH honeypot built in Python and containerised in Docker

# Installation

## Port forwarding
Setup port forwarding (e.g. from 22 to 2222)

iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 2222

## Generate server key
ssh-keygen -t rsa -f server.key

## Build
docker build -t basic_honeypot .

## Run
docker run -v ${PWD}:/usr/src/app -p 2222:2222 basic_honeypot
