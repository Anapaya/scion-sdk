#!/bin/bash

cargo +nightly fuzz run packet_parsing -c -O
