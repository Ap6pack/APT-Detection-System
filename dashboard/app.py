from flask import Flask, render_template, jsonify
import logging
from visualization import create_matplotlib_plot, create_plotly_plot

app = Flask(__name__)

@app.route('/')
def index():
    plot_url = create_matplotlib_plot()
    return render_template('index.html', plot_url=plot_url)

@app.route('/plotly')
def plotly():
    plot_json = create_plotly_plot()
    return jsonify(plot_json)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Flask app...")
    app.run(debug=True, use_reloader=False)
