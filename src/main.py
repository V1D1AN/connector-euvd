#!/usr/bin/env python3
"""
EUVD (European Union Vulnerability Database) Connector for OpenCTI
Main entry point for the connector.
"""

import sys
import traceback

try:
    from euvd import EUVDConnector
except Exception as e:
    print(f"Failed to import EUVDConnector: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

if __name__ == "__main__":
    try:
        connector = EUVDConnector()
        connector.run()
    except Exception as e:
        print(f"Connector failed: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
