"""Application entry point for LAN Share.

Keep the GUI implementation in lan_share.py for now. This small entry point
lets packaging and future modularization use a stable startup target.
"""

from lan_share import main


if __name__ == "__main__":
    main()
