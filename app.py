import os
from src import create_app

# Create the Flask app instance
app = create_app()

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT
    app.run(debug=False, host="0.0.0.0", port=port)
