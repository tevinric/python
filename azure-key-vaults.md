# Azure Key Vault Authentication - Simplified Guide

## Overview: Two Ways to Authenticate

Think of authentication like showing your ID card to access a building. Azure Key Vault needs to know "who" your application is before it can access secrets.

### Option 1: Managed Identity (The Easy Way)
**What it is**: Azure automatically creates and manages an identity for your application
**Think of it as**: A permanent employee ID badge that Azure gives to your app

### Option 2: Service Principal (The Manual Way)  
**What it is**: You manually create credentials (like username/password) for your application
**Think of it as**: Creating a visitor pass with login credentials

---

## When to Use Each Option

| Scenario | Use This | Why |
|----------|----------|-----|
| App running on Azure (App Service, Functions, VMs) | **Managed Identity** | Automatic, more secure, no passwords to manage |
| App running locally during development | **Service Principal** | Managed Identity doesn't work outside Azure |
| App running on your own servers/cloud | **Service Principal** | Managed Identity only works on Azure |
| App running on other clouds (AWS, GCP) | **Service Principal** | Managed Identity only works on Azure |

## Quick Decision Guide

**Ask yourself: "Where is my app running?"**

- ✅ **On Azure** → Use Managed Identity
- ❌ **Not on Azure** → Use Service Principal

---

## Option 1: Managed Identity Setup (Recommended for Azure Apps)

### What happens behind the scenes:
1. Azure creates a special identity for your app
2. Your app uses this identity automatically (no passwords needed)
3. You tell Key Vault to trust this identity

### Step-by-Step Setup

#### For Azure App Service:

```bash
# Step 1: Enable the identity for your app
az webapp identity assign --name myWebApp --resource-group myResourceGroup

# Step 2: Get the identity ID (Azure gives you this)
principalId=$(az webapp identity show --name myWebApp --resource-group myResourceGroup --query principalId --output tsv)

# Step 3: Tell Key Vault to trust this identity
az keyvault set-policy --name myKeyVault --object-id $principalId --secret-permissions get list
```

#### For Azure Functions:

```bash
# Step 1: Enable the identity for your function
az functionapp identity assign --name myFunctionApp --resource-group myResourceGroup

# Step 2: Get the identity ID
principalId=$(az functionapp identity show --name myFunctionApp --resource-group myResourceGroup --query principalId --output tsv)

# Step 3: Tell Key Vault to trust this identity
az keyvault set-policy --name myKeyVault --object-id $principalId --secret-permissions get list
```

### Python Code (Simple):

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# This automatically uses the managed identity
credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://your-vault.vault.azure.net/", credential=credential)

# Get a secret
secret = client.get_secret("my-secret-name")
print(secret.value)
```

### Pros and Cons:

**✅ Pros:**
- No passwords to store or rotate
- Azure manages everything automatically
- Most secure option
- No credentials in your code

**❌ Cons:**
- Only works when running on Azure
- Can't test locally (need Service Principal for local dev)

---

## Option 2: Service Principal Setup (For Non-Azure or Local Development)

### What happens behind the scenes:
1. You create a "user account" for your application in Azure
2. Azure gives you credentials (App ID + Password)
3. You store these credentials and use them to authenticate
4. You tell Key Vault to trust this "user account"

### Step-by-Step Setup

#### Step 1: Create the Service Principal

```bash
# Create a service principal (like creating a user account for your app)
az ad sp create-for-rbac --name myAppName --skip-assignment

# Azure will respond with something like this:
# {
#   "appId": "12345678-1234-1234-1234-123456789012",        # This is your username
#   "displayName": "myAppName",
#   "password": "abcd1234-efgh-5678-ijkl-mnop9012qrst",     # This is your password  
#   "tenant": "87654321-4321-4321-4321-210987654321"       # This is your organization ID
# }

# IMPORTANT: Save these values - you'll need them!
```

#### Step 2: Give Permission to Key Vault

```bash
# Tell Key Vault to trust your service principal
az keyvault set-policy \
  --name myKeyVault \
  --spn 12345678-1234-1234-1234-123456789012 \  # Use the appId from above
  --secret-permissions get list
```

#### Step 3: Store Credentials Securely

**For Local Development (.env file):**
```bash
# Create a .env file (NEVER commit this to git!)
AZURE_CLIENT_ID=12345678-1234-1234-1234-123456789012
AZURE_CLIENT_SECRET=abcd1234-efgh-5678-ijkl-mnop9012qrst
AZURE_TENANT_ID=87654321-4321-4321-4321-210987654321
KEY_VAULT_URL=https://your-vault.vault.azure.net/
```

**For Production Deployment:**
```bash
# Set environment variables in your hosting platform
# (Azure App Service, Docker, AWS, etc.)
export AZURE_CLIENT_ID="12345678-1234-1234-1234-123456789012"
export AZURE_CLIENT_SECRET="abcd1234-efgh-5678-ijkl-mnop9012qrst" 
export AZURE_TENANT_ID="87654321-4321-4321-4321-210987654321"
```

### Python Code:

```python
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential

# Read credentials from environment variables
client_id = os.environ['AZURE_CLIENT_ID']
client_secret = os.environ['AZURE_CLIENT_SECRET'] 
tenant_id = os.environ['AZURE_TENANT_ID']

# Create credential using the service principal
credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)

# Connect to Key Vault
client = SecretClient(vault_url="https://your-vault.vault.azure.net/", credential=credential)

# Get a secret
secret = client.get_secret("my-secret-name")
print(secret.value)
```

### Pros and Cons:

**✅ Pros:**
- Works anywhere (Azure, AWS, your laptop, etc.)
- Good for local development and testing
- Works across different cloud providers

**❌ Cons:**
- You have to manage passwords/secrets
- Need to rotate credentials periodically
- Risk of credentials being exposed
- More setup required

---

## Smart Python Code (Handles Both Options)

This code automatically chooses the right authentication method:

```python
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential

def get_keyvault_client(vault_url: str):
    """
    Smart function that picks the right authentication method
    """
    
    # Check if we have service principal credentials
    if all(key in os.environ for key in ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID']):
        print("Using Service Principal authentication")
        credential = ClientSecretCredential(
            tenant_id=os.environ['AZURE_TENANT_ID'],
            client_id=os.environ['AZURE_CLIENT_ID'],
            client_secret=os.environ['AZURE_CLIENT_SECRET']
        )
    else:
        print("Using Managed Identity authentication")
        credential = DefaultAzureCredential()
    
    return SecretClient(vault_url=vault_url, credential=credential)

# Usage
client = get_keyvault_client("https://your-vault.vault.azure.net/")
secret = client.get_secret("my-secret-name")
```

---

## Recommended Workflow

### For Development:
1. **Local Development**: Use Service Principal (create .env file)
2. **Testing on Azure**: Use Managed Identity

### For Production:
1. **Azure Hosting**: Always use Managed Identity
2. **Non-Azure Hosting**: Use Service Principal with secure credential storage

### Migration Path:
1. Start with Service Principal for development
2. Deploy to Azure using Managed Identity
3. Keep Service Principal as backup for local testing

---

## Security Best Practices

### For Service Principal:
- ✅ Store credentials in environment variables, never in code
- ✅ Use different service principals for different environments
- ✅ Rotate passwords regularly (every 6-12 months)
- ✅ Give minimal permissions (only "get" and "list" for secrets)
- ❌ Never commit credentials to version control

### For Managed Identity:
- ✅ Use system-assigned identity when possible
- ✅ Give minimal permissions
- ✅ Monitor access logs regularly
- ✅ Use separate Key Vaults for different environments

---

## Common Issues and Solutions

### "403 Forbidden" Error
**Problem**: Your app can authenticate but can't access secrets
**Solution**: Check Key Vault access policies - make sure you granted permissions

### "401 Unauthorized" Error  
**Problem**: Authentication is failing
**Solution**: 
- Service Principal: Check your credentials are correct
- Managed Identity: Make sure it's enabled on your Azure service

### Works locally but not in production
**Problem**: Different authentication methods
**Solution**: Use the smart code above that handles both methods

### Can't connect to Key Vault
**Problem**: Network or URL issues
**Solution**: 
- Check Key Vault URL format: `https://your-vault-name.vault.azure.net/`
- Verify firewall rules if using private endpoints

---

## Quick Test Script

Use this to verify your setup is working:

```python
import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential

def test_keyvault_connection():
    vault_url = "https://your-vault.vault.azure.net/"
    
    try:
        # Try the smart authentication method
        if all(key in os.environ for key in ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID']):
            credential = ClientSecretCredential(
                tenant_id=os.environ['AZURE_TENANT_ID'],
                client_id=os.environ['AZURE_CLIENT_ID'],
                client_secret=os.environ['AZURE_CLIENT_SECRET']
            )
            print("✅ Using Service Principal")
        else:
            credential = DefaultAzureCredential()
            print("✅ Using Managed Identity")
        
        client = SecretClient(vault_url=vault_url, credential=credential)
        
        # Try to list secrets (this tests permissions)
        secrets = list(client.list_properties_of_secrets())
        print(f"✅ Success! Found {len(secrets)} secrets")
        
        # List secret names
        for secret in secrets[:5]:  # Show first 5
            print(f"   - {secret.name}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

# Run the test
if __name__ == "__main__":
    test_keyvault_connection()
```

This simplified guide should help you choose and implement the right authentication method for your specific situation!
