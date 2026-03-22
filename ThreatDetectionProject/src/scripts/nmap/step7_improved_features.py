# We import pandas so we can load and work with tables (CSV files)
import pandas as pd

# We import IsolationForest for unsupervised anomaly detection
from sklearn.ensemble import IsolationForest

# We define a function that creates improved ML features from the raw port scan table
def build_features(df):
    # We create an "open" numeric feature: open=1 else 0
    df["open"] = df["state"].apply(lambda x: 1 if x == "open" else 0)

    # We create a "service_known" numeric feature: unknown=0 else 1
    df["service_known"] = df["service"].apply(lambda x: 0 if x == "unknown" else 1)

    # We define a set of common ports that are often normal in many networks
    common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389}

    # We create a feature that marks ports that are commonly seen
    df["port_is_common"] = df["port"].apply(lambda p: 1 if int(p) in common_ports else 0)

    # We create a feature to indicate if the port is a high ephemeral port (often suspicious when open)
    df["is_high_port"] = df["port"].apply(lambda p: 1 if int(p) >= 49152 else 0)

    # We create a feature for port bucket range (well-known vs registered vs dynamic)
    df["port_range_bucket"] = df["port"].apply(
        lambda p: 0 if int(p) <= 1023 else (1 if int(p) <= 49151 else 2)
    )

    # We define a small set of services that are often considered risky if exposed (example)
    risky_services = {"telnet", "ftp"}

    # We create a feature that flags risky services
    df["service_is_risky"] = df["service"].apply(lambda s: 1 if str(s).lower() in risky_services else 0)

    # We select only the numeric columns we want to feed into the ML model
    X = df[["port", "open", "service_known", "port_is_common", "is_high_port", "port_range_bucket", "service_is_risky"]]

    # We return the feature matrix (X) and the updated dataframe (df)
    return X, df

# This block runs only when you execute this script directly
if __name__ == "__main__":
    # We define the path to the raw ports CSV from your earlier step
    input_csv_path = "../output/scan1_ports.csv"

    # We load the CSV into a dataframe
    df = pd.read_csv(input_csv_path)

    # We build improved features and get X for training
    X, df = build_features(df)

    # We create an Isolation Forest model
    model = IsolationForest(
        n_estimators=300,      # We use more trees for stability
        contamination=0.25,    # We expect about 25% anomalies in small scan sets
        random_state=42        # We keep results reproducible
    )

    # We train the model and predict anomaly labels
    df["anomaly"] = model.fit_predict(X)

    # We compute anomaly severity scores (lower = more suspicious)
    df["anomaly_score"] = model.decision_function(X)

    # We sort results so the most suspicious appears first
    df_sorted = df.sort_values("anomaly_score", ascending=True)

    # We print a clean table for you to see the effect of improved features
    print(df_sorted[["ip", "port", "service", "open", "service_known", "port_is_common", "service_is_risky", "anomaly", "anomaly_score"]])

    # We save the results to a new CSV file
    df_sorted.to_csv("../output/improved_feature_results.csv", index=False)

    # We confirm the save
    print("\n✅ Saved to: ../output/improved_feature_results.csv")
