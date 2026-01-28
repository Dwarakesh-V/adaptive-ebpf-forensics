import time
import random
import json
from datetime import datetime

PROCESSES = ["ssh", "nginx", "python", "postgres"]
EVENTS = [
    "heap_overflow_detected",
    "use_after_free",
    "out_of_bounds_read",
    "suspicious_pointer_access"
]

def generate_event():
    event = {
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "process": random.choice(PROCESSES),
        "pid": random.randint(1000, 5000),
        "event": random.choice(EVENTS),
        "severity": random.choice(["LOW", "MEDIUM", "HIGH"])
    }
    return event

def event_stream():
    while True:
        event = generate_event()
        yield f"data: {json.dumps(event)}\n\n"
        time.sleep(1)
