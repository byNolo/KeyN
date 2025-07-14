import os
import sys
from dotenv import load_dotenv

# Add parent directory to path to access config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables from parent directory
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=6000)
