# We define a function to build human-readable explanation for a suspicious flow
def explain_flow(row):
    # If destination port is very high, flag ephemeral behavior
    if int(row["dst_port"]) >= 49152:
        return "High ephemeral destination port anomaly"

    # SSDP / UPnP multicast is usually 1900
    if int(row["dst_port"]) == 1900:
        return "SSDP multicast anomaly (UPnP)"

    # If many sources hit the same destination, could indicate scan/burst
    if int(row["unique_src_ips"]) > 5:
        return "Many unique sources targeting same destination"

    # If packet burst is large, it can be abnormal
    if int(row["packet_count"]) > 500:
        return "Unusual packet burst detected"

    # Default rule
    return "Statistical anomaly detected by Isolation Forest"


# We define a function that assigns severity using score thresholds
def severity_from_score(score):
    # Very low score means high risk
    if float(score) <= -0.20:
        return "HIGH"
    # Medium zone
    if float(score) <= -0.05:
        return "MEDIUM"
    # Otherwise low
    return "LOW"
# We define severity for unified model score
def unified_severity(score):
    # If score is very low, we mark HIGH severity
    if float(score) <= -0.20:
        return "HIGH"

    # If score is moderately low, we mark MEDIUM severity
    if float(score) <= -0.05:
        return "MEDIUM"

    # Otherwise we mark LOW severity
    return "LOW"