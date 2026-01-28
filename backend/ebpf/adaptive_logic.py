def adaptive_response(event):
    severity = event.get("severity")

    if severity == "HIGH":
        return {
            "action": "Enable deep memory tracing",
            "sampling_rate": "HIGH"
        }

    return {
        "action": "Normal monitoring",
        "sampling_rate": "LOW"
    }
