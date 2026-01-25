#!/usr/bin/env python3
"""
EUVD (European Union Vulnerability Database) Connector for OpenCTI
Main entry point for the connector.
"""

from euvd import EUVDConnector

if __name__ == "__main__":
    connector = EUVDConnector()
    connector.run()
