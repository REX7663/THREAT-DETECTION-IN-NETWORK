# Import pandas to read the CSV with anomaly results
import pandas as pd

# Import matplotlib to create graphs
import matplotlib.pyplot as plt

# Define the path to the anomaly results file
csv_path = "../output/scan1_with_anomalies.csv"

# Load the CSV into a DataFrame
df = pd.read_csv(csv_path)

# Separate normal and anomalous data
normal = df[df["anomaly"] == 1]      # All normal ports
anomalies = df[df["anomaly"] == -1]  # All suspicious ports

# Create a new figure
plt.figure()

# Plot normal ports (blue)
plt.scatter(normal.index, normal["port"], label="Normal")

# Plot anomalous ports (red)
plt.scatter(anomalies.index, anomalies["port"], label="Anomaly")

# Add title to the graph
plt.title("Isolation Forest Anomaly Detection Results")

# Label X-axis
plt.xlabel("Scan Index")

# Label Y-axis
plt.ylabel("Port Number")

# Add legend to differentiate normal vs anomaly
plt.legend()

# Save the figure into the output folder
plt.savefig("../output/anomaly_graph.png")

# Show the graph on screen
plt.show()

# Print confirmation
print("Graph saved to output/anomaly_graph.png")
