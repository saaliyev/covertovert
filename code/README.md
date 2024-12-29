# Covert Channel Implementation Using Packet Bursting and LLC Protocol

This project implements a covert channel using packet bursting with the Logical Link Control (LLC) protocol. The covert channel encodes binary data into bursts of packets sent over a network. This repository contains the implementation of both the sender and receiver for the covert channel, ensuring compliance with the assignment requirements.

---

## Features

- Encodes binary data into bursts of packets.
- Utilizes the LLC protocol for packet encoding and transmission.
- Includes termination signals to indicate the end of communication.
- Implements a decoding mechanism based on burst sizes.
- Configurable parameters for burst size, burst interval, and network interfaces.

---

## How It Works

1. Sender:
   - Generates a random binary message of length 128 (16 characters).
   - Encodes each bit (`0` or `1`) as a burst of packets based on a predefined burst mapping:
     - `0`: 1 packet
     - `1`: 2 packets
   - Adds a termination signal (".") at the end of the message.
   - Sends LLC packets with specified intervals between bursts.

2. Receiver:
   - Listens for incoming packets on the specified network interface.
   - Decodes received bursts into binary bits based on burst size.
   - Stops decoding upon detecting the termination signal.
   - Converts the binary message into its string representation.

---

## Covert Channel Capacity

To measure the covert channel capacity:
1. A binary message of length 128 was generated.
2. The timer was started before sending the first packet and stopped after sending the last packet.
3. The time difference in seconds was recorded.


### Results

- Total Time: X.XX seconds (replace with your calculated time).
- Covert Channel Capacity: XX.XX bps (replace with your calculated capacity).

---

## Configuration Parameters

The following parameters can be configured in the `config.json` file:

- Sender:
  - `log_file_name`: Name of the file to log the binary message.
  - `interface`: Network interface for sending packets.
  - `destination_mac`: Destination MAC address.
  - `burst_mapping`: Mapping of bits (`0`, `1`) to packet counts (e.g., `0`: 1 packet, `1`: 2 packets).
  - `burst_interval`: Time interval between bursts (in seconds).

- Receiver:
  - `log_file_name`: Name of the file to log the received message.
  - `interface`: Network interface for receiving packets.
  - `burst_interval`: Expected time interval between bursts (in seconds).
  - `burst_mapping`: Mapping of packet counts to bits (`1`: `0`, `2`: `1`).

---

## Limitations and Thresholds

- Minimum Burst Interval: The burst interval should not be too low, as it may result in packet collisions or missed bursts. The recommended minimum interval is 0.05 seconds.
- Maximum Burst Interval: Increasing the interval reduces capacity. A higher interval than 0.2 seconds significantly impacts performance.
- Packet Loss: Network conditions such as congestion can cause packet loss, affecting decoding accuracy.
- Termination Signal: The termination signal (".") ensures the receiver stops sniffing but may add slight overhead to the communication.



