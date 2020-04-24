#!/bin/bash
set -e

go generate
aws cloudformation create-stack --stack-name daishan-test --template-body file://./k3s-ec2-cloudformation.yaml --parameters file://./parameters.json

state=""
while [[ $state != "CREATE_COMPLETE" ]]
do
  state=$(aws cloudformation describe-stacks --stack-name daishan-test | jq -r .Stacks[0].StackStatus)
  echo "Waiting for stack to be completed"
  sleep 5
done
echo "Stack is Done"

DNSName=$(aws elbv2 describe-load-balancers --names k3s-nlb | jq -r .LoadBalancers[0].DNSName)
sed -i "s/server-url:6443/$DNSName/g" ./kubeconfig.yaml
echo "Setting Kubeconfig to $(pwd)/kubeconfig.yaml"
echo "export KUBECONFIG=$(pwd)/kubeconfig.yaml"