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






USage of KEY VAULTS:

# Azure Key Vault with Python Applications - Complete Guide

## Overview

Azure Key Vault is a secure cloud service for storing secrets, keys, and certificates. This guide covers how to set up and use Azure Key Vault with Python applications for secure configuration management.

## Prerequisites

- Azure subscription
- Python 3.7+
- Azure CLI installed
- Basic knowledge of Azure services

## Step 1: Create Azure Key Vault

### Using Azure Portal

1. Log into Azure Portal
2. Click "Create a resource"
3. Search for "Key Vault"
4. Fill in the required details:
   - **Resource Group**: Create new or select existing
   - **Key Vault Name**: Must be globally unique
   - **Region**: Choose appropriate region
   - **Pricing Tier**: Standard (Premium for HSM-backed keys)

### Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group (if needed)
az group create --name myResourceGroup --location eastus

# Create Key Vault
az keyvault create \
  --name myKeyVault \
  --resource-group myResourceGroup \
  --location eastus \
  --enabled-for-deployment true \
  --enabled-for-template-deployment true
```

## Step 2: Add Secrets to Key Vault

### Using Azure Portal

1. Navigate to your Key Vault
2. Click "Secrets" in the left menu
3. Click "Generate/Import"
4. Choose "Manual" upload type
5. Enter name and value for your secret

### Using Azure CLI

```bash
# Add individual secrets
az keyvault secret set --vault-name myKeyVault --name "database-connection-string" --value "Server=myserver;Database=mydb;..."
az keyvault secret set --vault-name myKeyVault --name "api-key" --value "your-api-key-here"
az keyvault secret set --vault-name myKeyVault --name "smtp-password" --value "your-smtp-password"

# Add multiple secrets from file
az keyvault secret set --vault-name myKeyVault --name "config-json" --file config.json
```

## Step 3: Set Up Authentication

### Option 1: Managed Identity (Recommended for Azure-hosted apps)

#### For Azure App Service
```bash
# Enable system-assigned managed identity
az webapp identity assign --name myWebApp --resource-group myResourceGroup

# Get the principal ID
principalId=$(az webapp identity show --name myWebApp --resource-group myResourceGroup --query principalId --output tsv)

# Grant access to Key Vault
az keyvault set-policy --name myKeyVault --object-id $principalId --secret-permissions get list
```

#### For Azure Functions
```bash
# Enable system-assigned managed identity
az functionapp identity assign --name myFunctionApp --resource-group myResourceGroup

# Grant access to Key Vault
principalId=$(az functionapp identity show --name myFunctionApp --resource-group myResourceGroup --query principalId --output tsv)
az keyvault set-policy --name myKeyVault --object-id $principalId --secret-permissions get list
```

### Option 2: Service Principal (For local development or non-Azure hosting)

```bash
# Create service principal
az ad sp create-for-rbac --name myApp --skip-assignment

# Note down the output:
# {
#   "appId": "your-app-id",
#   "displayName": "myApp",
#   "password": "your-password", 
#   "tenant": "your-tenant-id"
# }

# Grant access to Key Vault
az keyvault set-policy --name myKeyVault --spn your-app-id --secret-permissions get list
```

## Step 4: Install Python Dependencies

```bash
pip install azure-keyvault-secrets azure-identity python-dotenv
```

## Step 5: Python Implementation

### Basic Key Vault Client Setup

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import os
from typing import Dict, Optional

class KeyVaultManager:
    def __init__(self, vault_url: str):
        """
        Initialize Key Vault manager
        
        Args:
            vault_url: Azure Key Vault URL (https://your-vault.vault.azure.net/)
        """
        self.vault_url = vault_url
        self.credential = self._get_credential()
        self.client = SecretClient(vault_url=vault_url, credential=self.credential)
    
    def _get_credential(self):
        """Get appropriate Azure credential based on environment"""
        # For local development with service principal
        if all(key in os.environ for key in ['AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID']):
            return ClientSecretCredential(
                tenant_id=os.environ['AZURE_TENANT_ID'],
                client_id=os.environ['AZURE_CLIENT_ID'],
                client_secret=os.environ['AZURE_CLIENT_SECRET']
            )
        
        # For Azure-hosted applications with managed identity
        return DefaultAzureCredential()
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """
        Retrieve a secret from Key Vault
        
        Args:
            secret_name: Name of the secret to retrieve
            
        Returns:
            Secret value or None if not found
        """
        try:
            secret = self.client.get_secret(secret_name)
            return secret.value
        except Exception as e:
            print(f"Error retrieving secret '{secret_name}': {e}")
            return None
    
    def get_multiple_secrets(self, secret_names: list) -> Dict[str, str]:
        """
        Retrieve multiple secrets from Key Vault
        
        Args:
            secret_names: List of secret names to retrieve
            
        Returns:
            Dictionary of secret names and values
        """
        secrets = {}
        for name in secret_names:
            value = self.get_secret(name)
            if value:
                secrets[name] = value
        return secrets
    
    def list_secrets(self) -> list:
        """List all secret names in the Key Vault"""
        try:
            return [secret.name for secret in self.client.list_properties_of_secrets()]
        except Exception as e:
            print(f"Error listing secrets: {e}")
            return []
```

### Configuration Management Class

```python
import json
from dataclasses import dataclass
from typing import Any, Dict

@dataclass
class AppConfig:
    """Application configuration loaded from Key Vault"""
    database_url: str
    api_key: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    debug: bool = False
    
    @classmethod
    def from_keyvault(cls, kv_manager: KeyVaultManager):
        """Load configuration from Key Vault"""
        secrets = kv_manager.get_multiple_secrets([
            'database-connection-string',
            'api-key',
            'smtp-host',
            'smtp-port',
            'smtp-username',
            'smtp-password',
            'debug-mode'
        ])
        
        return cls(
            database_url=secrets.get('database-connection-string', ''),
            api_key=secrets.get('api-key', ''),
            smtp_host=secrets.get('smtp-host', ''),
            smtp_port=int(secrets.get('smtp-port', '587')),
            smtp_username=secrets.get('smtp-username', ''),
            smtp_password=secrets.get('smtp-password', ''),
            debug=secrets.get('debug-mode', '').lower() == 'true'
        )

class ConfigManager:
    """Centralized configuration manager"""
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def initialize(self, vault_url: str):
        """Initialize configuration from Key Vault"""
        if self._config is None:
            kv_manager = KeyVaultManager(vault_url)
            self._config = AppConfig.from_keyvault(kv_manager)
    
    @property
    def config(self) -> AppConfig:
        """Get application configuration"""
        if self._config is None:
            raise RuntimeError("Configuration not initialized. Call initialize() first.")
        return self._config
```

### Flask Application Example

```python
from flask import Flask, jsonify
import os

app = Flask(__name__)

# Initialize configuration
config_manager = ConfigManager()
config_manager.initialize(os.environ.get('KEY_VAULT_URL', 'https://your-vault.vault.azure.net/'))

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'debug_mode': config_manager.config.debug
    })

@app.route('/config-status')
def config_status():
    """Check if configuration is loaded properly"""
    config = config_manager.config
    return jsonify({
        'database_configured': bool(config.database_url),
        'api_key_configured': bool(config.api_key),
        'smtp_configured': bool(config.smtp_host and config.smtp_username)
    })

if __name__ == '__main__':
    app.run(debug=config_manager.config.debug)
```

### Django Settings Integration

```python
# settings.py
import os
from .keyvault_config import KeyVaultManager

# Initialize Key Vault
VAULT_URL = os.environ.get('KEY_VAULT_URL', 'https://your-vault.vault.azure.net/')
kv_manager = KeyVaultManager(VAULT_URL)

# Load secrets
DATABASE_PASSWORD = kv_manager.get_secret('database-password')
SECRET_KEY = kv_manager.get_secret('django-secret-key')
EMAIL_HOST_PASSWORD = kv_manager.get_secret('email-password')

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'myapp'),
        'USER': os.environ.get('DB_USER', 'myuser'),
        'PASSWORD': DATABASE_PASSWORD,
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Email configuration
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_USER')
EMAIL_HOST_PASSWORD = EMAIL_HOST_PASSWORD
```

## Step 6: Environment Configuration

### For Local Development (.env file)

```bash
# .env file for local development
KEY_VAULT_URL=https://your-vault.vault.azure.net/
AZURE_CLIENT_ID=your-service-principal-app-id
AZURE_CLIENT_SECRET=your-service-principal-password
AZURE_TENANT_ID=your-tenant-id
```

### For Azure App Service

```bash
# Set application settings in Azure App Service
az webapp config appsettings set --name myWebApp --resource-group myResourceGroup --settings \
  KEY_VAULT_URL=https://your-vault.vault.azure.net/
```

### For Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Don't copy secrets - they'll come from Key Vault
ENV KEY_VAULT_URL=""

CMD ["python", "app.py"]
```

## Step 7: Error Handling and Retry Logic

```python
import time
from azure.core.exceptions import ServiceRequestError
from functools import wraps

def retry_on_failure(max_retries=3, delay=1):
    """Decorator for retrying Key Vault operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ServiceRequestError as e:
                    if attempt == max_retries - 1:
                        raise e
                    print(f"Attempt {attempt + 1} failed, retrying in {delay} seconds...")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

class RobustKeyVaultManager(KeyVaultManager):
    @retry_on_failure(max_retries=3, delay=2)
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret with retry logic"""
        return super().get_secret(secret_name)
```

## Step 8: Caching for Performance

```python
import time
from typing import Dict, Tuple
from threading import Lock

class CachedKeyVaultManager(KeyVaultManager):
    def __init__(self, vault_url: str, cache_ttl: int = 300):  # 5 minutes default
        super().__init__(vault_url)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = Lock()
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret with caching"""
        current_time = time.time()
        
        with self._lock:
            # Check cache first
            if secret_name in self._cache:
                value, timestamp = self._cache[secret_name]
                if current_time - timestamp < self.cache_ttl:
                    return value
            
            # Fetch from Key Vault
            value = super().get_secret(secret_name)
            if value:
                self._cache[secret_name] = (value, current_time)
            
            return value
    
    def clear_cache(self):
        """Clear the secret cache"""
        with self._lock:
            self._cache.clear()
```

## Best Practices

### Security Best Practices

1. **Use Managed Identity**: Always prefer managed identity over service principals for Azure-hosted applications
2. **Principle of Least Privilege**: Grant only necessary permissions (get, list) not (set, delete)
3. **Rotate Secrets Regularly**: Implement secret rotation policies
4. **Monitor Access**: Enable Key Vault logging and monitoring
5. **Separate Environments**: Use different Key Vaults for dev/staging/prod

### Performance Best Practices

1. **Cache Secrets**: Implement caching to reduce API calls
2. **Batch Operations**: Retrieve multiple secrets in one operation when possible
3. **Connection Pooling**: Reuse Key Vault client instances
4. **Async Operations**: Use async client for high-throughput applications

### Operational Best Practices

1. **Health Checks**: Implement health checks that verify Key Vault connectivity
2. **Fallback Strategies**: Have fallback configurations for critical services
3. **Secret Naming**: Use consistent naming conventions (e.g., `service-environment-secret`)
4. **Documentation**: Document all secrets and their purposes

## Monitoring and Logging

### Enable Key Vault Logging

```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --workspace-name myLogWorkspace \
  --resource-group myResourceGroup

# Enable diagnostic logging
az monitor diagnostic-settings create \
  --name KeyVaultDiagnostics \
  --resource-id /subscriptions/{subscription-id}/resourceGroups/myResourceGroup/providers/Microsoft.KeyVault/vaults/myKeyVault \
  --workspace myLogWorkspace \
  --logs '[{"category":"AuditEvent","enabled":true}]' \
  --metrics '[{"category":"AllMetrics","enabled":true}]'
```

### Application Logging

```python
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LoggingKeyVaultManager(KeyVaultManager):
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret with logging"""
        logger.info(f"Retrieving secret: {secret_name}")
        try:
            value = super().get_secret(secret_name)
            logger.info(f"Successfully retrieved secret: {secret_name}")
            return value
        except Exception as e:
            logger.error(f"Failed to retrieve secret {secret_name}: {e}")
            raise
```

## Troubleshooting Common Issues

### Authentication Issues

```python
# Test authentication
def test_keyvault_access():
    try:
        kv_manager = KeyVaultManager(os.environ['KEY_VAULT_URL'])
        secrets = kv_manager.list_secrets()
        print(f"Successfully connected. Found {len(secrets)} secrets.")
        return True
    except Exception as e:
        print(f"Authentication failed: {e}")
        return False
```

### Common Error Solutions

1. **403 Forbidden**: Check access policies and permissions
2. **401 Unauthorized**: Verify authentication credentials
3. **404 Not Found**: Check Key Vault URL and secret names
4. **Network Issues**: Verify firewall rules and network connectivity

This comprehensive guide should help you implement Azure Key Vault integration with your Python applications securely and efficiently.
