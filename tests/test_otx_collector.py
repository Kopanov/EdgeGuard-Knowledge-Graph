#!/usr/bin/env python3
"""Quick OTX test"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

# Fresh imports
for mod in list(sys.modules.keys()):
    if any(x in mod for x in ["collector", "config"]):
        try:
            del sys.modules[mod]
        except (KeyError, ModuleNotFoundError):
            pass

from collectors.otx_collector import OTXCollector

c = OTXCollector()
results = c.collect(limit=10)
print(f"OTX collected: {len(results)}")
if results:
    print("First:", results[0])
