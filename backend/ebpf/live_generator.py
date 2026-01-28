import time
import random
import json
from datetime import datetime
from zoneinfo import ZoneInfo

PROCESSES = ["ssh", "nginx", "python", "postgres"]
EVENTS = [
    "heap_overflow_detected",
    "use_after_free",
    "out_of_bounds_read",
    "suspicious_pointer_access"
]

def generate_event():
    event = {
        "time": datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%H:%M:%S"),
        "process": random.choice(PROCESSES),
        "pid": random.randint(1000, 5000),
        "event": random.choice(EVENTS),
        "severity": random.choices(
                                    ["LOW", "MEDIUM", "HIGH"],
                                    weights=[70, 20, 10],
                                    k=1
                                )[0]

    }
    return event

def event_stream(buffer):
    while True:
        event = generate_event()
        buffer.append(event)
        yield f"data: {json.dumps(event)}\n\n"
        time.sleep(1)
