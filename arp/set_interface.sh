#!/bin/bash

ifconfig | awk '/br-/{print $1}' > interface