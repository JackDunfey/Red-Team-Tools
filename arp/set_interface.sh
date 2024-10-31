#!/bin/bash

ifconfig | awk -F: '/br-/{print $1}' > interface