# Google Cloud Model Armor Setup Guide

This guide explains how to set up Google Cloud authentication for the Model Armor threat detection provider.

## Prerequisites

1. **Google Cloud Project**: You need an active Google Cloud project
2. **Security Command Center**: Model Armor is part of Google Cloud Security Command Center
3. **Billing**: Ensure billing is enabled on your project
4. **APIs**: Enable the Security Command Center API

## Setup Options

### Option 1: Service Account Key (Recommended for Development)

1. **Create a Service Account**:
   ```bash
   gcloud iam service-accounts create model-armor-service \
       --description="Service account for Model Armor threat detection" \
       --display-name="Model Armor Service"
   ```

2. **Grant Required Permissions**:
   ```bash
   gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
       --member="serviceAccount:model-armor-service@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
       --role="roles/securitycenter.admin"
   ```

3. **Create and Download Key**:
   ```bash
   gcloud iam service-accounts keys create ~/model-armor-key.json \
       --iam-account=model-armor-service@YOUR_PROJECT_ID.iam.gserviceaccount.com
   ```

4. **Configure Environment Variables**:
   ```bash
   export GOOGLE_MODEL_ARMOR_ENABLED=true
   export GOOGLE_MODEL_ARMOR_PROJECT_ID=YOUR_PROJECT_ID
   export GOOGLE_MODEL_ARMOR_SERVICE_ACCOUNT_PATH=/path/to/model-armor-key.json
   export GOOGLE_MODEL_ARMOR_MODE=monitor
   ```

### Option 2: Application Default Credentials (Recommended for Production)

1. **Install Google Cloud SDK**:
   ```bash
   # On Ubuntu/Debian
   curl https://sdk.cloud.google.com | bash
   exec -l $SHELL
   
   # On macOS
   brew install google-cloud-sdk
   ```

2. **Authenticate**:
   ```bash
   gcloud auth application-default login
   ```

3. **Set Default Project**:
   ```bash
   gcloud config set project YOUR_PROJECT_ID
   ```

4. **Configure Environment Variables**:
   ```bash
   export GOOGLE_MODEL_ARMOR_ENABLED=true
   export GOOGLE_MODEL_ARMOR_PROJECT_ID=YOUR_PROJECT_ID
   export GOOGLE_MODEL_ARMOR_MODE=monitor
   ```

## Enable Required APIs

```bash
# Enable Security Command Center API
gcloud services enable securitycenter.googleapis.com

# Verify the API is enabled
gcloud services list --enabled --filter="name:securitycenter.googleapis.com"
```

## Configuration Examples

### Development Configuration (.env file)
```bash
# Google Model Armor Configuration
GOOGLE_MODEL_ARMOR_ENABLED=true
GOOGLE_MODEL_ARMOR_PROJECT_ID=my-project-123
GOOGLE_MODEL_ARMOR_LOCATION=global
GOOGLE_MODEL_ARMOR_SERVICE_ACCOUNT_PATH=/home/user/keys/model-armor-key.json
GOOGLE_MODEL_ARMOR_MODE=monitor
```

### Production Configuration (using ADC)
```bash
# Google Model Armor Configuration
GOOGLE_MODEL_ARMOR_ENABLED=true
GOOGLE_MODEL_ARMOR_PROJECT_ID=my-production-project
GOOGLE_MODEL_ARMOR_LOCATION=global
GOOGLE_MODEL_ARMOR_MODE=block
```

## Testing the Setup

1. **Install Dependencies**:
   ```bash
   pip install --upgrade google-cloud-modelarmor google-auth
   ```

2. **Test Authentication**:
   ```python
   from google.cloud import securitycenter
   from google.auth import default
   
   try:
       credentials, project = default()
       client = securitycenter.SecurityCenterClient(credentials=credentials)
       print(f"✅ Authentication successful for project: {project}")
   except Exception as e:
       print(f"❌ Authentication failed: {e}")
   ```

3. **Run Threat Detection Test**:
   ```bash
   cd backend-agent
   python test_threat_detection.py
   ```

## Troubleshooting

### Common Issues

1. **"Default credentials not found"**
   - Solution: Run `gcloud auth application-default login` or set `GOOGLE_APPLICATION_CREDENTIALS`

2. **"Permission denied"**
   - Solution: Ensure the service account has `roles/securitycenter.admin` or appropriate permissions

3. **"Project not found"**
   - Solution: Verify the project ID is correct and the project exists

4. **"API not enabled"**
   - Solution: Enable the Security Command Center API: `gcloud services enable securitycenter.googleapis.com`

### Debug Commands

```bash
# Check current authentication
gcloud auth list

# Check current project
gcloud config get-value project

# Check enabled APIs
gcloud services list --enabled | grep security

# Test API access
gcloud alpha security-center assets list --organization=YOUR_ORG_ID
```

## Security Best Practices

1. **Principle of Least Privilege**: Only grant necessary permissions
2. **Key Rotation**: Regularly rotate service account keys
3. **Environment Separation**: Use different service accounts for dev/staging/prod
4. **Key Storage**: Never commit service account keys to version control
5. **Monitoring**: Enable audit logging for security-related API calls

## Cost Considerations

- Model Armor pricing is based on the number of requests
- Monitor usage through Google Cloud Console
- Set up billing alerts to avoid unexpected charges
- Consider using quotas to limit API usage

## Support

- **Google Cloud Documentation**: https://cloud.google.com/security-command-center/docs
- **API Reference**: https://cloud.google.com/security-command-center/docs/reference
- **Support**: Use Google Cloud Support for API-specific issues

## Next Steps

After setting up Google Cloud authentication:

1. Configure other threat detection providers (Azure, OpenAI)
2. Set up custom rules for your specific use case
3. Configure monitoring and alerting
4. Test the system with your actual workloads
5. Set up production deployment with proper security measures
