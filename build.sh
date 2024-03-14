#!/usr/bin/env bash

PWD=$( pwd )  # record current working dir

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

cd $DIR  # this should be the Pycharm project directory

source ./.venv/bin/activate  # activate python virtual environment

rm -rf ./build/siteDiscovery
rm -rf ./dist/siteDiscovery
rm -f ./dist/siteDiscovery
rm -f ./siteDiscovery.spec

# build to one exe file
pyinstaller --clean --noconfirm --onefile main.py \
  --add-data playbook.yaml:. --add-data artifacts:artifacts \
  --name siteDiscovery \

chmod +x ./dist/siteDiscovery

#source ./.venv/bin/deactivate

cd $PWD  # get back to working dir
