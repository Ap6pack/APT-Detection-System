from data_preprocessing.load_dataset import load_data
from data_preprocessing.data_cleaning import clean_data
from data_preprocessing.feature_engineering import extract_features

def run(file_path):
    df = load_data(file_path)
    df = clean_data(df)
    df = extract_features(df)
    return df

# Testing the preprocessing module
if __name__ == "__main__":
    df = run('~/../synthetic_apt_dataset.csv')
    print(df.head())
