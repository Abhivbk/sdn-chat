#!/bin/bash
MODE=${1:-sdn}
source ~/ryu-env/bin/activate
SDN_MODE=$MODE ryu-manager --verbose sdn_controller.py
