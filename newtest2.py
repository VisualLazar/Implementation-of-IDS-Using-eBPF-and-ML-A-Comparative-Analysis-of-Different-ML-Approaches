import socket
import logging
from scapy.all import sniff
import subprocess
import threading
import time

# Set up logging configuration with info level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize packet counting and timing variables
packet_count = 0
total_processing_time = 0.0
lock = threading.Lock()

# Function to start the C++ IDS application
def start_ids_application():
    try:
        subprocess.Popen(["./ebpf_wrapper"])
        logging.info("IDS application started successfully.")
    except Exception as e:
        logging.error(f"Failed to start IDS application: {e}")

# Function to report packet processing statistics every interval
def report_statistics():
    global packet_count, total_processing_time
    while True:
        time.sleep(10)  # Reporting interval: 10 seconds
        with lock:
            print("\n================== Performance Report ==================")
            print(f"Time Interval: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
            print(f"Packets Processed: {packet_count}")
            if packet_count > 0:
                average_time_per_packet = total_processing_time / packet_count
                print(f"Average Processing Time per Packet: {average_time_per_packet:.6f} seconds")
            else:
                print("No packets processed in the last interval.")
            print("========================================================\n")
            # Reset counters after each interval
            packet_count = 0
            total_processing_time = 0.0

# Function to send packets to the IDS via a persistent socket
def packet_callback(packet, sock):
    global packet_count, total_processing_time
    try:
        packet_data = bytes(packet)
        start_time = time.time()
        sock.sendall(packet_data)
        end_time = time.time()
        processing_time = end_time - start_time
        with lock:
            packet_count += 1
            total_processing_time += processing_time
    except Exception as e:
        logging.error(f"Error processing or sending packet: {e}")

# Main function to manage IDS application startup, sniffing, and performance reporting
def main():
    start_ids_application()
    time.sleep(10)
    ids_address = '192.168.86.131' # IP-address may vary. Change IP-address to match the IDS host.
    ids_port = 9000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((ids_address, ids_port))
            # Start a separate thread for periodic performance reporting
            reporter_thread = threading.Thread(target=report_statistics)
            reporter_thread.daemon = True
            reporter_thread.start()
            # Start packet sniffing with the persistent connection
            sniff(prn=lambda x: packet_callback(x, sock), filter="ip", store=False)
        except Exception as e:
            logging.error(f"Error during connection or sniffing: {e}")

if __name__ == "__main__":
    main()

