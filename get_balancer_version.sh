#!/bin/bash
BALANCER_REV=$(git rev-list HEAD --count)
BEAM_MAJOR=$(grep -oP '^set\(VERSION_MAJOR\ \K\d+(?=\))' ./beam/CMakeLists.txt)
BEAM_MINOR=$(grep -oP '^set\(VERSION_MINOR\ \K\d+(?=\))' ./beam/CMakeLists.txt)
BEAM_REV=$(git -C ./beam rev-list HEAD --count)

BALANCER_VERSION=$BEAM_MAJOR.$BEAM_MINOR.$BEAM_REV.$BALANCER_REV
echo $BALANCER_VERSION
