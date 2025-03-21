import torch
import numpy as np

class AIThreatDetector:
    """A simple AI model for identifying malicious patterns."""
    
    def __init__(self):
        self.model = self._load_dummy_model()

    def _load_dummy_model(self):
        """Loads a simple AI model (placeholder for now)."""
        return lambda x: "⚠️ Potential anomaly detected!" if np.random.rand() > 0.8 else "✅ Safe request."

    def analyze_request(self, request_data):
        """Analyzes request data for potential threats."""
        return self.model(request_data)

detector = AIThreatDetector()
print(detector.analyze_request("SELECT * FROM users WHERE username='admin'"))
print(detector.analyze_request("SELECT * FROM users WHERE username='user'"))