import matplotlib.pyplot as plt
import io
import base64
import pandas as pd
import plotly.express as px

def create_matplotlib_plot():
    # Sample data for demonstration
    data = {'x': [1, 2, 3, 4, 5], 'y': [10, 15, 13, 17, 20]}
    df = pd.DataFrame(data)

    fig, ax = plt.subplots()
    ax.plot(df['x'], df['y'], marker='o')

    # Save the plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)

    # Encode the image to base64
    plot_url = base64.b64encode(img.getvalue()).decode()

    return plot_url

def create_plotly_plot():
    # Sample data for demonstration
    data = {'x': [1, 2, 3, 4, 5], 'y': [10, 15, 13, 17, 20]}
    df = pd.DataFrame(data)

    fig = px.line(df, x='x', y='y', title='Sample Plotly Line Chart')

    # Convert Plotly figure to JSON
    fig_json = fig.to_json()

    return fig_json
