#!/bin/bash

# Set colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting deployment of FROST Access Control System${NC}"

# Step 1: Install dependencies
echo -e "${GREEN}Installing dependencies...${NC}"
npm install

# Step 2: Compile smart contracts
echo -e "${GREEN}Compiling smart contracts...${NC}"
npx truffle compile

# Step 3: Start local blockchain for testing
echo -e "${GREEN}Starting local blockchain...${NC}"
npx ganache-cli -d &
GANACHE_PID=$!
sleep 5 # Wait for Ganache to start

# Step 4: Deploy smart contracts
echo -e "${GREEN}Deploying smart contracts...${NC}"
npx truffle migrate --network development

# Step 5: Get contract address
CONTRACT_ADDRESS=$(npx truffle networks | grep -A1 "FROSTAccessControl" | tail -n 1 | awk -F': ' '{print $2}' | tr -d ',')
echo -e "${GREEN}Contract deployed at: ${CONTRACT_ADDRESS}${NC}"

# Step 6: Update contract address in API server
echo -e "${GREEN}Updating API server configuration...${NC}"
sed -i "s/YOUR_CONTRACT_ADDRESS/${CONTRACT_ADDRESS}/g" src/api/server.js

# Step 7: Package API server
echo -e "${GREEN}Packaging API server...${NC}"
mkdir -p dist
cp -r src dist/
cp package.json dist/
cd dist && npm install --production && cd ..

# Step 8: Create Lambda deployment package
echo -e "${GREEN}Creating Lambda deployment package...${NC}"
cd dist && zip -r ../lambda_function.zip . && cd ..

# Step 9: Deploy to cloud (using Terraform)
echo -e "${GREEN}Deploying to AWS using Terraform...${NC}"
cd terraform/aws
terraform init
terraform apply -auto-approve
cd ../..

echo -e "${GREEN}Deploying to Azure using Terraform...${NC}"
cd terraform/azure
terraform init
terraform apply -auto-approve
cd ../..

# Step 10: Clean up local blockchain
echo -e "${GREEN}Cleaning up...${NC}"
kill $GANACHE_PID

echo -e "${YELLOW}Deployment complete!${NC}"

# Display output
AWS_API_URL=$(cd terraform/aws && terraform output -raw api_gateway_url)
AZURE_API_URL=$(cd terraform/azure && terraform output -raw api_gateway_url)

echo -e "${GREEN}AWS API Gateway URL: ${AWS_API_URL}${NC}"
echo -e "${GREEN}Azure API URL: ${AZURE_API_URL}${NC}"

echo -e "${YELLOW}To run the API Gateway locally:${NC}"
echo "npm start"