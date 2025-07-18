import time
from flask import Flask, render_template

app = Flask(__name__)

# Configure cache busting with automatic versioning
app.config['CACHE_VERSION'] = str(int(time.time()))

@app.context_processor
def inject_cache_version():
    return dict(cache_version=app.config['CACHE_VERSION'])

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=6001)
