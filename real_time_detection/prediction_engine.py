def run(models):
    # Use models for real-time prediction
    def predict(data):
        predictions = {}
        for model_name, model in models.items():
            predictions[model_name] = model.predict(data)
        return predictions

# Testing prediction engine
if __name__ == "__main__":
    class MockModel:
        def predict(self, data):
            return [0]

    models = {'model1': MockModel(), 'model2': MockModel()}
    data = [1, 2, 3, 4, 5]
    predictions = run(models).predict(data)
    print(predictions)
