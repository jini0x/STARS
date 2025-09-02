# Docker Setup for STARS with Google Model Armor

This guide explains how to run the STARS backend with Google Cloud Model Armor integration using Docker Compose.

## Prerequisites

1. **Google Cloud SDK**: Install and authenticate with Google Cloud
   ```bash
   # Install Google Cloud SDK
   curl https://sdk.cloud.google.com | bash
   exec -l $SHELL
   
   # Authenticate and set up Application Default Credentials
   gcloud auth application-default login
   gcloud config set project YOUR_PROJECT_ID
   ```

2. **Docker and Docker Compose**: Ensure Docker and Docker Compose are installed

3. **Environment Configuration**: Set up your `.env` file in the `backend-agent` directory

## Setup Instructions

### 1. Configure Environment Variables

Copy the threat detection example configuration:
```bash
cp backend-agent/.env.threat_detection.example backend-agent/.env
```

Edit `backend-agent/.env` and configure your Google Model Armor settings:
```bash
# Google Model Armor Configuration
GOOGLE_MODEL_ARMOR_ENABLED=true
GOOGLE_MODEL_ARMOR_PROJECT_ID=your-gcp-project-id
GOOGLE_MODEL_ARMOR_LOCATION=us-central1
GOOGLE_MODEL_ARMOR_TEMPLATE_ID=your-template-id
GOOGLE_MODEL_ARMOR_MODE=monitor

# Enable threat detection
THREAT_DETECTION_ENABLED=true
THREAT_DETECTION_MODE=monitor
```

### 2. Run with Docker Compose

#### Option A: Full Stack (Frontend + Backend)
```bash
# Build and run both frontend and backend
docker-compose up --build

# Run in detached mode
docker-compose up -d --build
```

#### Option B: Backend Only
```bash
# Build and run only the backend service
docker-compose -f docker-compose.backend.yml up --build

# Run in detached mode
docker-compose -f docker-compose.backend.yml up -d --build
```

#### Option C: Equivalent Docker Run Command
The Docker Compose setup is equivalent to this docker run command:
```bash
docker run \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/gcp/creds.json:ro" \
  -v $(pwd)/backend-agent:/app \
  --env GOOGLE_APPLICATION_CREDENTIALS=/gcp/creds.json \
  -p 8080:8080 \
  --env-file backend-agent/.env \
  stars-backend-2
```

## Docker Compose Files

### `docker-compose.yml` (Full Stack)
- Runs both frontend (port 3000) and backend (port 8080)
- Includes Google Cloud credentials mounting
- Sets up networking between services

### `docker-compose.backend.yml` (Backend Only)
- Runs only the backend service (port 8080)
- Mounts Google Cloud credentials
- Mounts the backend-agent directory for development

## Google Cloud Credentials

The setup automatically mounts your Google Cloud Application Default Credentials from:
```
~/.config/gcloud/application_default_credentials.json
```

This file is created when you run:
```bash
gcloud auth application-default login
```

## Accessing the Services

- **Backend API**: http://localhost:8080
- **Frontend** (full stack only): http://localhost:3000

## Testing the Setup

1. **Check if the backend is running**:
   ```bash
   curl http://localhost:8080/health
   ```

2. **Test Google Model Armor integration**:
   ```bash
   # Copy the test file to the container and run it
   docker-compose exec stars-backend python test_google_model_armor.py
   ```

3. **View logs**:
   ```bash
   # Full stack
   docker-compose logs -f backend
   
   # Backend only
   docker-compose -f docker-compose.backend.yml logs -f stars-backend
   ```

## Troubleshooting

### Common Issues

1. **Google Cloud credentials not found**:
   ```bash
   # Ensure you're authenticated
   gcloud auth application-default login
   
   # Check if credentials file exists
   ls -la ~/.config/gcloud/application_default_credentials.json
   ```

2. **Permission denied on credentials file**:
   ```bash
   # Fix permissions
   chmod 600 ~/.config/gcloud/application_default_credentials.json
   ```

3. **Project ID not set**:
   ```bash
   # Set default project
   gcloud config set project YOUR_PROJECT_ID
   
   # Or set in .env file
   echo "GOOGLE_MODEL_ARMOR_PROJECT_ID=your-project-id" >> backend-agent/.env
   ```

4. **API not enabled**:
   ```bash
   # Enable required APIs
   gcloud services enable securitycenter.googleapis.com
   ```

### Debug Commands

```bash
# Check container environment
docker-compose exec stars-backend env | grep GOOGLE

# Check mounted credentials
docker-compose exec stars-backend ls -la /gcp/

# Check if Google Cloud libraries are installed
docker-compose exec stars-backend python -c "from google.cloud import modelarmor_v1; print('✅ Google Cloud libraries available')"

# Run the standalone test
docker-compose exec stars-backend python test_google_model_armor.py
```

## Development Mode

For development, the backend-only compose file mounts the source code directory:
```bash
# Start in development mode
docker-compose -f docker-compose.backend.yml up --build

# Code changes will be reflected immediately (if using a development server)
```

## Stopping Services

```bash
# Stop full stack
docker-compose down

# Stop backend only
docker-compose -f docker-compose.backend.yml down

# Stop and remove volumes
docker-compose down -v
```

## Security Notes

- The Google Cloud credentials are mounted as read-only (`:ro`)
- Credentials are not copied into the image, only mounted at runtime
- The `.env` file should not be committed to version control
- Use different service accounts for different environments (dev/staging/prod)
