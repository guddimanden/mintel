#!/bin/bash

commands=(
#    'ulimit -n 999999;ulimit -u999999; zmap -p 80 -T6 -w mass.zone  | go run massloader.go 81'
    'ulimit -n 999999;ulimit -u999999; zmap -p 8081 -T6 -w mass.zone  | go run massloader.go 8081'
    'ulimit -n 999999;ulimit -u999999; zmap -p 80 -T6 -w mass.zone  | go run massloader.go 80'    
    'ulimit -n 999999;ulimit -u999999; zmap -p 8080 -T6 -w mass.zone| go run massloader.go 8080'
    'bash scan.sh'
)

for cmd in "${commands[@]}"; do
    echo "Running command: $cmd"
    eval "$cmd"
    echo "Command finished"
done
