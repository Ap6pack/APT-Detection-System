from sklearn.model_selection import cross_val_score

def run(model, df):
    X = df.drop('target', axis=1)
    y = df['target']
    scores = cross_val_score(model, X, y, cv=5)
    return scores

# Testing cross-validation
if __name__ == "__main__":
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    data = {'feature1': [1, 2, 3, 4, 5], 'feature2': [5, 4, 3, 2, 1], 'target': [0, 1, 0, 1, 0]}
    df = pd.DataFrame(data)
    model = RandomForestClassifier()
    scores = run(model, df)
    print(f'Cross-Validation Scores: {scores}')
