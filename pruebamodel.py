import joblib
import pandas as pd

model = joblib.load('model.pkl')

# Datos de prueba
data = pd.DataFrame([{
    'DIM( Days In Milk)': 50,
    'Avg(7 days). Daily MY( L )': 30,
    'Kg. milk 305 ( Kg )': 1000,
    'Fat (%)': 4.0,
    'SNF (%)': 8.0,
    'Density ( Kg/ m3': 1.03,
    'Protein (%)': 3.5,
    'Conductivity (mS/cm)': 5.0,
    'pH': 6.7,
    'Freezing point (⁰C)': -0.5,
    'Salt (%)': 0.2,
    'Lactose (%)': 4.8
}])

# Predicción
print(model.predict(data))