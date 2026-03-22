# We import pandas to load the CSV file
import pandas as pd

# We import IsolationForest from scikit-learn for anomaly detection
from sklearn.ensemble import IsolationForest

# We define the path to the CSV file created earlier
csv_path = "../output/scan1_ports.csv"

# Load the CSV file into a pandas DataFrame
df = pd.read_csv(csv_path)

# ---------------------------
# FEATURE ENGINEERING SECTION
# ---------------------------

# Create a new column called "open"
# If state is "open", assign 1, otherwise 0
df["open"] = df["state"].apply(lambda x: 1 if x == "open" else 0)

# Create a new column called "service_known"
# If service is not "unknown", assign 1, otherwise 0
df["service_known"] = df["service"].apply(lambda x: 0 if x == "unknown" else 1)

# ---------------------------
# SELECT FEATURES FOR ML
# ---------------------------

# Select only numeric features for the ML model
# We use port number, open status, and service_known
X = df[["port", "open", "service_known"]]

# ---------------------------
# TRAIN ISOLATION FOREST
# ---------------------------

# Create the Isolation Forest model
# contamination=0.25 means we assume about 25% of data could be anomalies
model = IsolationForest(
    n_estimators=100,     # Number of trees in the forest
    contamination=0.25,   # Percentage of anomalies expected
    random_state=42       # Ensures reproducible results
)

# Train the model and predict anomalies
df["anomaly"] = model.fit_predict(X)

# ---------------------------
# OUTPUT RESULTS
# ---------------------------

# Print the DataFrame with anomaly labels
print("Anomaly Detection Results:")
print(df[["ip", "port", "service", "anomaly"]])

# Save results to a new CSV file
df.to_csv("../output/scan1_with_anomalies.csv", index=False)

# Confirm save
print("\nResults saved to output/scan1_with_anomalies.csv")
