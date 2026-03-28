#!/usr/bin/env python3
"""
EdgeGuard - Additional Threat Feed Collectors (DEPRECATED)

⚠️ DEPRECATED: This module is kept for backward compatibility.
Please use global_feed_collector.py instead for new code.

This module re-exports from global_feed_collector to maintain compatibility
with existing imports.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import warnings

logger = logging.getLogger(__name__)

# Emit deprecation warning
warnings.warn(
    "additional_feeds_collector is deprecated. Use global_feed_collector instead.", DeprecationWarning, stacklevel=2
)

# Re-export from global_feed_collector for backward compatibility
from collectors.global_feed_collector import (
    get_zones_from_malware,
)

# Re-export detect_zones_from_text from config for backward compatibility

# Keep old function name for backward compatibility
get_sector_from_malware = get_zones_from_malware


def test():
    """Test collectors (deprecated, use global_feed_collector.test instead)"""
    logger.warning("Using deprecated additional_feeds_collector. Please migrate to global_feed_collector.")
    from collectors.global_feed_collector import test as global_test

    return global_test()


if __name__ == "__main__":
    test()
