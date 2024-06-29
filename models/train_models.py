from .lighgbm_model import train as train_lgbm
from .bilstm_model import train as train_bilstm
from .hybrid_classifier import combine

def run(df):
    lgbm_model = train_lgbm(df)
    bilstm_model = train_bilstm(df)
    hybrid_model = combine(lgbm_model, bilstm_model)
    return lgbm_model, bilstm_model, hybrid_model
