#!/bin/bash
set -e

export FAKE_DNS=$(ip addr show docker0 | awk 'match($0, /([0-9.]+)\/[0-9]+/, a) { print a[1] }')
sed -i -e s/127.0.0.1:5002/${FAKE_DNS}:5002/ configs/integration-boulder.ini

export GOPATH=~/build/go
mkdir -p $GOPATH/src/github.com/letsencrypt/
git clone https://github.com/letsencrypt/boulder.git $GOPATH/src/github.com/letsencrypt/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder

docker compose up -d

echo 'waiting for boulder to be functional ...'

while true; do
  curl --silent --show-error http://127.0.0.1:4001/directory && break
  sleep 1
  if [[ "$SECONDS" -gt 300 ]]; then
    echo 'setup took more than 5 minutes, give up  :-('
    docker compose logs
    exit 3
  fi
done

docker compose logs
