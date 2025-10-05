provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "frost" {
  name     = "frost-resources"
  location = "East US"
}

resource "azurerm_app_service_plan" "frost" {
  name                = "frost-appserviceplan"
  location            = azurerm_resource_group.frost.location
  resource_group_name = azurerm_resource_group.frost.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_app_service" "frost_api" {
  name                = "frost-api-gateway"
  location            = azurerm_resource_group.frost.location
  resource_group_name = azurerm_resource_group.frost.name
  app_service_plan_id = azurerm_app_service_plan.frost.id
  
  site_config {
    linux_fx_version = "NODE|16-lts"
  }

  app_settings = {
    "CONTRACT_ADDRESS" = "0x0000000000000000000000000000000000000000" # To be updated after deployment
    "PROVIDER_URL"     = "https://mainnet.infura.io/v3/YOUR_INFURA_KEY" # Replace with your Ethereum node URL
    "AZURE_TENANT_ID"  = "your-tenant-id"
    "AZURE_CLIENT_ID"  = "your-client-id"
    "AZURE_CLIENT_SECRET" = "your-client-secret"
  }
}

resource "azurerm_application_insights" "frost" {
  name                = "frost-appinsights"
  location            = azurerm_resource_group.frost.location
  resource_group_name = azurerm_resource_group.frost.name
  application_type    = "web"
}

output "api_gateway_url" {
  value = "https://${azurerm_app_service.frost_api.default_site_hostname}"
}