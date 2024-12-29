from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, LLC, get_if_hwaddr, sniff
import time


class MyCovertChannel(CovertChannelBase):
    

    def __init__(self):
        super().__init__()

    def send(self, log_file_name, interface, destination_mac,burst_mapping,burst_interval):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, max_length=16, min_length=16)

        termination_signal = self.convert_string_message_to_binary(".")
        binary_message += termination_signal
        source_mac = get_if_hwaddr(interface)

        for bit in binary_message:
            num_packets = burst_mapping.get(bit,3) 
            for _ in range(num_packets):
                packet = Ether(src=source_mac,dst=destination_mac)/ LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
                super().send(packet,interface=interface)

            time.sleep(burst_interval)

    def receive(self, log_file_name, interface, burst_interval, burst_mapping):
        received_binary_message=""
        burst_start_time=None
        current_burst_count=0
        termination_detected= False  

        inverse_mapping = {v: k for k, v in burst_mapping.items()}  

        def control(packet):
            nonlocal received_binary_message,burst_start_time,current_burst_count,termination_detected

            now = time.time()

            if burst_start_time is None:
                burst_start_time = now

            if now-burst_start_time<burst_interval:
                current_burst_count+=1
            else:
                received_bit= inverse_mapping.get(current_burst_count, "0")  
                received_binary_message += received_bit

                burst_start_time= now
                current_burst_count =1

                if "." in "".join(
                    self.convert_eight_bits_to_character(received_binary_message[i:i+ 8])
                    for i in range(0, len(received_binary_message), 8)
                ):
                    termination_detected = True
                    return True  
        try:
            sniff(
                iface=interface,
                prn=control,
                stop_filter=lambda _: termination_detected,
                store=0
            )
        except KeyboardInterrupt:
            print("Sniffing stopped manually.")

        received_message = "".join(
            self.convert_eight_bits_to_character(received_binary_message[i:i+ 8])
            for i in range(0, len(received_binary_message), 8)
        )
        self.log_message(received_message,log_file_name)
        return received_message