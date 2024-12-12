az account set -s 37deca37-c375-4a14-b90a-043849bd2bf1


az network public-ip create \
  --resource-group isaac-euap-002 \
  --name myAGPublicIPAddress \
  --allocation-method Static \
  --sku Standard


az network vnet subnet create \
  --name myAGSubnet \
  --resource-group isaac-euap-002 \
  --vnet-name custvnet \
  --address-prefix 10.16.5.0/24

az network application-gateway waf-policy create \
  --resource-group isaac-euap-002 \
  --name myWafPolicy \
  --location eastus2euap

az network application-gateway create \
  --name myAppGateway \
  --location eastus2euap \
  --resource-group isaac-euap-002 \
  --capacity 2 \
  --sku WAF_v2 \
  --public-ip-address myAGPublicIPAddress \
  --vnet-name custvnet \
  --subnet myAGSubnet \
  --servers 10.16.1.27 \
  --priority 100 \
 --waf-policy myWafPolicy
