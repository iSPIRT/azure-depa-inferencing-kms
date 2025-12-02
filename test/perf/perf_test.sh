#!/bin/bash

export KMS_URL=https://depa-inferencing-kms.centralindia.cloudapp.azure.com

wrk --connections 100 --threads 100 --duration 30s --latency ${KMS_URL}/app/listpubkeys 