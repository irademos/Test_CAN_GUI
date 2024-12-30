# CAN Communication GUI

This project is a GUI application built using Python's `tkinter` library that allows for communication with a CAN bus. It supports sending and receiving CAN messages and logs the communication for debugging purposes.

## Features

- **CAN Bus Connection**: Establish a connection to a CAN bus via a specified COM port and bitrate.
- **Send Test Message**: Send a predefined test CAN message to the connected CAN bus.
- **Listen for CAN Messages**: Start/Stop the listening process to receive and process CAN messages.
- **Logging**: Logs all messages received and sent to a file (`can_messages.log`) for review.
- **Display**: Provides a scrolling text area to show CAN communication activity.

## Requirements

- Python 3.x
- `tkinter` (included with Python)
- `python-can` library

You can install `python-can` via pip:

```bash
pip install python-can
