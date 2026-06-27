import logging
import sys
import os
from pythonjsonlogger import jsonlogger

def setup_logger(name: str = "triad_sentinel") -> logging.Logger:
    """
    Setup logger that automatically detects GCP environment and sends logs to Cloud Logging.
    Falls back to console logging for local development.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid adding handlers multiple times if setup_logger is called repeatedly
    if logger.handlers:
        return logger
        
    # Check if running on GCP (Vertex AI / Cloud Run / GCE)
    is_gcp_environment = any([
        os.getenv('K_SERVICE'),  # Cloud Run
        os.getenv('CLOUD_ML_REGION'),  # Vertex AI
        os.getenv('GCE_METADATA_HOST'),  # GCE
        os.getenv('FUNCTION_NAME')  # Cloud Functions
    ])
    
    if is_gcp_environment:
        # Production: Use Google Cloud Logging
        try:
            from google.cloud import logging as cloud_logging
            client = cloud_logging.Client()
            handler = client.get_handler(logger_name=name)
            handler.setLevel(logging.INFO)
            logger.info(f"Cloud Logging enabled for {name}")
        except Exception as e:
            # Fallback to console if Cloud Logging fails
            logger.warning(f"Cloud Logging setup failed: {e}, falling back to console")
            handler = logging.StreamHandler(sys.stdout)
    else:
        # Local Development: Use console logging with JSON format
        handler = logging.StreamHandler(sys.stdout)
        # Use JSON formatter for structured logs
        formatter = jsonlogger.JsonFormatter(
            fmt='%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d',
            datefmt='%Y-%m-%dT%H:%M:%S'
        )
        handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger
