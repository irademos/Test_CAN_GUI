import tkinter as tk
from tkinter import scrolledtext
import can
import logging
import time
import threading
import can.interfaces.slcan

class CANApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CAN Communication GUI")

        self.listening = False
        self.listening_thread = None  # Thread for listening process 
        
        # Configure logging
        logging.basicConfig(filename="can_messages.log", level=logging.INFO, format="%(asctime)s - %(message)s")

        # Input fields
        tk.Label(root, text="COM Port:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.com_port_entry = tk.Entry(root, width=15)
        self.com_port_entry.grid(row=0, column=1, padx=5, pady=5)
        self.com_port_entry.insert(0, "COM0")  # Default value

        tk.Label(root, text="Bitrate:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.bitrate_entry = tk.Entry(root, width=15)
        self.bitrate_entry.grid(row=1, column=1, padx=5, pady=5)
        self.bitrate_entry.insert(0, "100000")  # Default value

        # Buttons
        tk.Button(root, text="Start CAN", command=self.start_can).grid(row=2, column=1, padx=70, pady=5, sticky="e")
        tk.Button(root, text="Send Test Message", command=self.send_test_message).grid(row=3, column=0, padx=20, pady=5, sticky="w")
        self.test_button = tk.Button(root, text="Get PWB Status", command=self.toggle_listening)
        self.test_button.grid(row=3, column=1, padx=0, pady=5, sticky="w")



        # Output console
        self.console = scrolledtext.ScrolledText(root, width=50, height=15, state="disabled")
        self.console.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        # CAN bus object
        self.bus = None

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log_message(self, message):
        try:
            """Display a message in the console and log it."""
            self.console.config(state="normal")
            self.console.insert(tk.END, message + "\n")
            self.console.see(tk.END)  # Auto-scroll
            self.console.config(state="disabled")
            logging.info(message)
        except Exception as e:
            self.log_message(f"Error: {e}")

    def close_can_bus(self):
        """Properly close the CAN bus when the app is closed."""
        if self.bus:
            try:
                self.bus.shutdown()
                self.log_message("CAN bus closed.")
            except Exception as e:
                self.log_message(f"Error closing CAN bus: {e}")

    def on_closing(self):
        """Handle the window close event to ensure proper cleanup."""
        self.listening = False  # Stop the listening process
        self.close_can_bus()
        self.root.destroy()

    def start_can(self):
        """Initialize the CAN bus."""
        com_port = self.com_port_entry.get()
        bitrate = int(self.bitrate_entry.get())
        try:
            self.bus = can.interface.Bus(bustype='slcan', channel=com_port, bitrate=bitrate)
            # self.bus = can.interface.Bus(bustype='gs_usb', channel=0, bitrate=bitrate)
            self.log_message(f"Connected to CAN bus on {com_port} with bitrate {bitrate}.")
        except Exception as e:
            self.log_message(f"Error starting CAN bus: {e}")

    def toggle_listening(self):
        """Start or stop the listening process."""
        self.log_message('button pressed')
        self.listening = not self.listening
        if self.listening:
            self.test_button.config(text="Stop")
            self.listening_thread = threading.Thread(target=self.listening_process, daemon=True)
            self.listening_thread.start()
        else:
            self.test_button.config(text="Get PWB Status")
            self.log_message("Stop signal received. Listening will stop shortly.")

    def listening_process(self):
        """Listen for CAN messages in a separate thread."""
        if not self.bus:
            self.log_message("Error: CAN bus not initialized.")
            self.listening = False
            self.test_button.config(text="Get PWB Status")
            return

        try:
            # record data from pwb
            received_a2 = False
            received_a3 = False
            received_f1 = False   
            canTimeout = False
            battHarnFault = False
            count = 0

            self.log_message("Listening for CAN messages.")
            while self.listening:  # Stop if flag is set
                message = None
                try:
                    message = self.bus.recv(timeout=1)  # Receive message with a 1-second timeout
                except can.CanError as e:
                    self.log_message(f"Error: {e}")
                    continue
                if message:
                    # Check for the fixed CAN ID 0x055
                    # self.log_message(str(message.data))
                    if message.arbitration_id == 0x055:
                        count = count + 1

                        data = list(message.data)
                        first_byte = data[0]

                        # Log received message
                        self.log_message(f"Data = 0x {' '.join(f'{byte:02X}' for byte in message.data)}")

                        # Process based on the first byte of data
                        if first_byte == 0xA2:
                            a2_bytes = data[1:]  # Save bytes 2 through 8
                            received_a2 = True
                            # self.log_message(f"A2 Bytes Saved: {a2_bytes}")

                        elif first_byte == 0xA3:
                            if data[3] & 0x80:  # Check bit 1 of byte 4 (index 3)
                                shaftPowerOff = True
                            else:
                                shaftPowerOff = False
                            received_a3 = True
                            # self.log_message("Shaft Power Off detected (A3).")

                        elif first_byte == 0xF1:
                            if data[5] == 0x40:  # Check for "40" in byte 6 (index 5)
                                canTimeout = True
                                # self.log_message("CAN Timeout detected (F1).")
                            if data[4] == 0x18:  # Check for "18" in byte 5 (index 4)
                                battHarnFault = True
                                # self.log_message("Battery Harness Fault detected (F1).")
                            received_f1 = True

                        # Break if all required messages are received
                        # if received_a2 and received_a3 and received_f1:
                        if count > 50:
                            self.log_message("Count > 50. Ending.")
                            # self.log_message("All required messages received. Exiting early.")
                            break
        
        except (IndexError, AttributeError) as e:
            self.log_message(f"Error: {e}")
        finally:
            self.test_button.config(text="Get PWB Status")
            if not self.listening:
                self.log_message("Listening stopped.")
                # Log final results
            self.listening = False  # Reset the stop flag 
            try:
                self.log_message(f"24V Controller Voltage: {a2_bytes[0]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: 24V Controller Voltage message not received.")
            try:
                self.log_message(f"24V Car Voltage: {a2_bytes[1]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: 24V Car Voltage message not received.")
            try:
                self.log_message(f"24V Car Light: {a2_bytes[2]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: 24V Car Light message not received.")
            try:
                self.log_message(f"Safety Voltage: {a2_bytes[3]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: Safety Voltage message not received.")
            try:
                self.log_message(f"Door Voltage: {a2_bytes[4]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: Door Voltage message not received.")
            try:
                self.log_message(f"Brake Voltage: {a2_bytes[5]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: Brake Voltage message not received.")
            try:
                self.log_message(f"Emergency Voltage: {a2_bytes[6]}V")
            except (IndexError, AttributeError):
                self.log_message("Error: Emergency Voltage message not received.")
            try:
                if shaftPowerOff:
                    self.log_message("Shaft Power is Off. Try sending the Test Message again.")
            except AttributeError:
                self.log_message("Error: Shaft Power Off status not available.")
            if canTimeout:
                self.log_message("Fault: The PWB has not received a CAN message for more than 10 seconds.")
            if battHarnFault:
                self.log_message("Fault: The battery is connected, but the battery temp sensor harness is not connected.")


    def send_test_message(self):
        """Send a test CAN message."""
        if not self.bus:
            self.log_message("Error: CAN bus not initialized.")
            return
        try:
            # send the test data
            msg = can.Message(
                arbitration_id=0x56,
                data = [0xB1, 0xBE, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00],    #[0, 25, 0, 1, 3, 1, 4, 1],
                is_extended_id=False        # double check this
            )
            self.bus.send(msg)
            self.log_message(f"Message sent: ID={msg.arbitration_id}, Data={list(msg.data)}")

        except can.CanError as e:
            self.log_message(f"Failed to send message: {e}")
        finally:
            self.log_message(f"Completed.")



if __name__ == "__main__":
    root = tk.Tk()
    app = CANApp(root)
    root.mainloop()
