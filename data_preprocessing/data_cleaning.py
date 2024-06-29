def clean_data(df):
    df.ffill(inplace=True)
    df.bfill(inplace=True)
    return df