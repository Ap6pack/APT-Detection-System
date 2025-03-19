import os
import yaml
import logging
from flask import Flask, render_template, jsonify
from visualization import create_matplotlib_plot, create_plotly_plot

app = Flask(__name__)

def load_config():
    """Load configuration from config.yaml file."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)

@app.route('/')
def index():
    plot_url = create_matplotlib_plot()
    return render_template('index.html', plot_url=plot_url)

@app.route('/plotly')
def plotly():
    plot_json = create_plotly_plot()
    return jsonify(plot_json)

@app.route('/models')
def models():
    """Display information about saved models."""
    config = load_config()
    model_info = {
        'lightgbm': os.path.exists(config['model_paths']['lightgbm']),
        'bilstm': os.path.exists(config['model_paths']['bilstm']),
    }
    return render_template('models.html', model_info=model_info)

def run(host=None, port=None, debug=None):
    """Run the Flask application with configurable parameters."""
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Flask app...")
    
    # If parameters not provided, load from config
    if host is None or port is None or debug is None:
        config = load_config()
        host = host or config['dashboard']['host']
        port = port or config['dashboard']['port']
        debug = debug if debug is not None else config['dashboard']['debug']
    
    app.run(host=host, port=port, debug=debug, use_reloader=False)

if __name__ == '__main__':
    run()
