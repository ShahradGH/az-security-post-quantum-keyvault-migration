param location string = resourceGroup().location
resource mhsm 'Microsoft.KeyVault/managedHSMs@2023-07-01' = {
  name: 'mhsm-sovereign-pqc'
  location: location
  sku: { family: 'B', name: 'Standard_B1' }
  properties: { tenantId: subscription().tenantId, enablePurgeProtection: true }
}
