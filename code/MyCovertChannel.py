from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, LLC, get_if_hwaddr, sniff
import time


class MyCovertChannel(CovertChannelBase):
    """
    Implements a covert channel using LLC packets with burst-based encoding and decoding.
    Sends bursts of packets to encode binary data.
    """

    def __init__(self):
        super().__init__()

    def send(self, log_file_name, interface, destination_mac, burst_mapping, burst_interval):
        """
        Sends binary data encoded in LLC packets using bursts.
        Each burst represents a value based on `burst_mapping`.
        Burst interval specifies the time between bursts (in seconds).

        Args:
            log_file_name (str): Name of the log file for the binary message.
            interface (str): Network interface for sending packets.
            destination_mac (str): Destination MAC address.
            burst_mapping (dict): Mapping of bit values ('0', '1', etc.) to packet counts.
            burst_interval (float): Time between bursts in seconds.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, max_length=16, min_length=16)

        # Add termination signal (".")
        termination_signal = self.convert_string_message_to_binary(".")
        binary_message += termination_signal

        # Get the source MAC address
        source_mac = get_if_hwaddr(interface)

        for bit in binary_message:
            # Determine the number of packets to send in the burst
            num_packets = burst_mapping.get(bit, 3)  # Default to 3 packets if mapping not found

            for _ in range(num_packets):
                # Construct the LLC packet
                packet = Ether(src=source_mac, dst=destination_mac) / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
                super().send(packet, interface=interface)

            # Add a delay between bursts
            time.sleep(burst_interval)

    def receive(self, log_file_name, interface, burst_interval, burst_mapping):
        """
        Receives LLC packets and decodes the binary message based on burst sizes.
        Stops sniffing and returns when the termination signal (.) is detected.

        Args:
            log_file_name (str): Name of the log file for the received message.
            interface (str): Network interface for sniffing packets.
            burst_interval (float): Time between bursts in seconds.
            burst_mapping (dict): Mapping of packet counts to bit values ('0', '1', etc.).
        """
        received_binary_message = ""
        burst_start_time = None
        current_burst_count = 0
        termination_detected = False  # Flag to indicate termination

        inverse_mapping = {v: k for k, v in burst_mapping.items()}  # Reverse the mapping for decoding

        def packet_handler(packet):
            nonlocal received_binary_message, burst_start_time, current_burst_count, termination_detected

            now = time.time()

            if burst_start_time is None:
                burst_start_time = now

            if now - burst_start_time < burst_interval:
                # Count packets within the current burst window
                current_burst_count += 1
            else:
                # Process the completed burst
                print(f"Burst complete. Packet count: {current_burst_count}")

                # Decode the burst count into a bit
                received_bit = inverse_mapping.get(current_burst_count, "0")  # Default to "0" if mapping not found
                received_binary_message += received_bit

                # Debug: Print received binary message every 8 bits
                if len(received_binary_message) % 8 == 0:
                    print(f"Received binary so far: {received_binary_message}")

                # Reset for the next burst
                burst_start_time = now
                current_burst_count = 1

                # Check for termination signal
                if "." in "".join(
                    self.convert_eight_bits_to_character(received_binary_message[i:i + 8])
                    for i in range(0, len(received_binary_message), 8)
                ):
                    print("Termination signal detected.")
                    termination_detected = True
                    return True  # This stops sniffing but doesn't force return

        print(f"Sniffing on interface: {interface}")

        try:
            sniff(
                iface=interface,
                prn=packet_handler,
                stop_filter=lambda _: termination_detected,
                store=0
            )
        except KeyboardInterrupt:
            print("Sniffing stopped manually.")

        # Convert binary to a string message
        received_message = "".join(
            self.convert_eight_bits_to_character(received_binary_message[i:i + 8])
            for i in range(0, len(received_binary_message), 8)
        )

        # Log the received message
        self.log_message(received_message, log_file_name)

        print(f"Final received message: {received_message}")
        return received_message