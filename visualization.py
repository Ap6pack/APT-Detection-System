import matplotlib.pyplot as plt
import io
import base64
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any

def create_matplotlib_plot():
    """
    Create a sample Matplotlib plot for demonstration.
    
    Returns:
        Base64-encoded PNG image
    """
    # Sample data for demonstration
    data = {'x': [1, 2, 3, 4, 5], 'y': [10, 15, 13, 17, 20]}
    df = pd.DataFrame(data)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df['x'], df['y'], marker='o', linewidth=2)
    ax.set_title('Sample Matplotlib Plot')
    ax.set_xlabel('X Axis')
    ax.set_ylabel('Y Axis')
    ax.grid(True)

    # Save the plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=100, bbox_inches='tight')
    img.seek(0)

    # Encode the image to base64
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    # Close the figure to free memory
    plt.close(fig)

    return plot_url

def create_plotly_plot():
    """
    Create a sample Plotly plot for demonstration.
    
    Returns:
        JSON representation of the Plotly figure
    """
    # Sample data for demonstration
    data = {'x': [1, 2, 3, 4, 5], 'y': [10, 15, 13, 17, 20]}
    df = pd.DataFrame(data)

    fig = px.line(
        df, 
        x='x', 
        y='y', 
        title='Sample Plotly Line Chart',
        labels={'x': 'X Axis', 'y': 'Y Axis'},
        template='plotly_white'
    )
    
    fig.update_layout(
        title_font_size=20,
        xaxis_title_font_size=16,
        yaxis_title_font_size=16,
        legend_title_font_size=16,
        height=500
    )

    # Convert Plotly figure to JSON
    fig_json = fig.to_json()

    return fig_json

def create_entity_behavior_plot(entity_counts: Dict[str, int]) -> str:
    """
    Create a bar chart of entity alert counts.
    
    Args:
        entity_counts: Dictionary mapping entity names to alert counts
        
    Returns:
        JSON representation of the Plotly figure
    """
    if not entity_counts:
        # Create empty plot if no data
        fig = go.Figure()
        fig.update_layout(
            title="No Entity Data Available",
            xaxis_title="Entity",
            yaxis_title="Alert Count",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Convert to DataFrame
    df = pd.DataFrame({
        'entity': list(entity_counts.keys()),
        'count': list(entity_counts.values())
    })
    
    # Sort by count descending
    df = df.sort_values('count', ascending=False)
    
    # Take top 10 entities
    if len(df) > 10:
        df = df.head(10)
    
    # Create bar chart
    fig = px.bar(
        df,
        x='entity',
        y='count',
        title='Top Entities by Alert Count',
        labels={'entity': 'Entity', 'count': 'Alert Count'},
        color='count',
        color_continuous_scale='Viridis',
        template='plotly_white'
    )
    
    fig.update_layout(
        title_font_size=20,
        xaxis_title_font_size=16,
        yaxis_title_font_size=16,
        height=500,
        coloraxis_showscale=False
    )
    
    # Rotate x-axis labels if there are many entities
    if len(df) > 5:
        fig.update_layout(
            xaxis_tickangle=-45
        )
    
    return fig.to_json()

def create_alert_timeline_plot(alerts: List[Dict[str, Any]]) -> str:
    """
    Create a timeline plot of alerts.
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        JSON representation of the Plotly figure
    """
    if not alerts:
        # Create empty plot if no data
        fig = go.Figure()
        fig.update_layout(
            title="No Alert Data Available",
            xaxis_title="Date",
            yaxis_title="Alert Count",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Extract timestamps and convert to datetime
    timestamps = []
    severities = []
    
    for alert in alerts:
        timestamp = alert.get('timestamp')
        if timestamp:
            try:
                # Convert to datetime
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                timestamps.append(dt)
                severities.append(alert.get('severity', 'Unknown'))
            except (ValueError, TypeError):
                pass
    
    if not timestamps:
        # Create empty plot if no valid timestamps
        fig = go.Figure()
        fig.update_layout(
            title="No Alert Timeline Data Available",
            xaxis_title="Date",
            yaxis_title="Alert Count",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Create DataFrame
    df = pd.DataFrame({
        'timestamp': timestamps,
        'severity': severities
    })
    
    # Add date column
    df['date'] = df['timestamp'].dt.date
    
    # Count alerts by date and severity
    date_severity_counts = df.groupby(['date', 'severity']).size().reset_index(name='count')
    
    # Create stacked bar chart
    fig = px.bar(
        date_severity_counts,
        x='date',
        y='count',
        color='severity',
        title='Alert Timeline',
        labels={'date': 'Date', 'count': 'Alert Count', 'severity': 'Severity'},
        color_discrete_map={
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#6c757d',
            'Unknown': '#adb5bd'
        },
        template='plotly_white'
    )
    
    fig.update_layout(
        title_font_size=20,
        xaxis_title_font_size=16,
        yaxis_title_font_size=16,
        legend_title_font_size=16,
        height=500,
        barmode='stack'
    )
    
    return fig.to_json()

def create_entity_feature_plot(behavior: Dict[str, Any]) -> str:
    """
    Create a radar chart of entity features.
    
    Args:
        behavior: Entity behavior dictionary
        
    Returns:
        JSON representation of the Plotly figure
    """
    if not behavior or 'statistics' not in behavior:
        # Create empty plot if no data
        fig = go.Figure()
        fig.update_layout(
            title="No Entity Feature Data Available",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Extract feature statistics
    statistics = behavior.get('statistics', {})
    
    # Features to include in radar chart
    feature_names = [
        'network_traffic_volume_mean',
        'number_of_logins_mean',
        'number_of_failed_logins_mean',
        'number_of_accessed_files_mean',
        'number_of_email_sent_mean',
        'cpu_usage_mean',
        'memory_usage_mean',
        'disk_io_mean',
        'network_latency_mean',
        'number_of_processes_mean'
    ]
    
    # Filter to features that exist in statistics
    available_features = [f for f in feature_names if f in statistics]
    
    if not available_features:
        # Create empty plot if no available features
        fig = go.Figure()
        fig.update_layout(
            title="No Entity Feature Data Available",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Extract current and mean values
    current_values = []
    mean_values = []
    max_values = []
    
    for feature in available_features:
        stats = statistics.get(feature, {})
        current_values.append(stats.get('current', 0))
        mean_values.append(stats.get('mean', 0))
        max_values.append(stats.get('max', 0))
    
    # Create radar chart
    fig = go.Figure()
    
    # Add current values
    fig.add_trace(go.Scatterpolar(
        r=current_values,
        theta=available_features,
        fill='toself',
        name='Current',
        line_color='#007bff'
    ))
    
    # Add mean values
    fig.add_trace(go.Scatterpolar(
        r=mean_values,
        theta=available_features,
        fill='toself',
        name='Mean',
        line_color='#28a745'
    ))
    
    # Add max values
    fig.add_trace(go.Scatterpolar(
        r=max_values,
        theta=available_features,
        fill='toself',
        name='Max',
        line_color='#dc3545'
    ))
    
    # Update layout
    fig.update_layout(
        title=f"Feature Analysis for {behavior.get('entity', 'Unknown')}",
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, max(max(current_values), max(mean_values), max(max_values)) * 1.1]
            )
        ),
        showlegend=True,
        template='plotly_white',
        height=600
    )
    
    return fig.to_json()

def create_severity_distribution_plot(severity_counts: Dict[str, int]) -> str:
    """
    Create a pie chart of alert severity distribution.
    
    Args:
        severity_counts: Dictionary mapping severity levels to counts
        
    Returns:
        JSON representation of the Plotly figure
    """
    if not severity_counts or sum(severity_counts.values()) == 0:
        # Create empty plot if no data
        fig = go.Figure()
        fig.update_layout(
            title="No Severity Data Available",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Convert to DataFrame
    df = pd.DataFrame({
        'severity': list(severity_counts.keys()),
        'count': list(severity_counts.values())
    })
    
    # Create pie chart
    fig = px.pie(
        df,
        values='count',
        names='severity',
        title='Alert Severity Distribution',
        color='severity',
        color_discrete_map={
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#6c757d',
            'Unknown': '#adb5bd'
        },
        template='plotly_white'
    )
    
    fig.update_layout(
        title_font_size=20,
        legend_title_font_size=16,
        height=500
    )
    
    return fig.to_json()

def create_source_distribution_plot(source_counts: Dict[str, int]) -> str:
    """
    Create a pie chart of alert source distribution.
    
    Args:
        source_counts: Dictionary mapping source types to counts
        
    Returns:
        JSON representation of the Plotly figure
    """
    if not source_counts or sum(source_counts.values()) == 0:
        # Create empty plot if no data
        fig = go.Figure()
        fig.update_layout(
            title="No Source Data Available",
            template='plotly_white'
        )
        return fig.to_json()
    
    # Convert to DataFrame
    df = pd.DataFrame({
        'source': list(source_counts.keys()),
        'count': list(source_counts.values())
    })
    
    # Create pie chart
    fig = px.pie(
        df,
        values='count',
        names='source',
        title='Alert Source Distribution',
        template='plotly_white'
    )
    
    fig.update_layout(
        title_font_size=20,
        legend_title_font_size=16,
        height=500
    )
    
    return fig.to_json()
