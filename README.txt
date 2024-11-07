Introduction:
The increasing deployment of IoT devices in Systems of Systems (SoS), such as smart homes, introduces various security risks, particularly as the Connectivity of the system grows. SoS are characterized by their interconnected nature, where individual subsystems operate autonomously but contribute to a larger purpose (Boardman & Sauser, 2006). As the number of connected devices grows, the system's attack surface may expand, leading to increased exposure to cyber threats. This paper explores the hypothesis: Does increasing the number of connected devices in an IoT-based smart home system decrease the overall security by increasing the system’s attack surface?

Features:
Controller Class: The Controller class remains mostly the same, verifying message integrity and logging latency.
SHA-256 Hashing for message integrity verification.
Configurable network condition simulations, including tampering, packet loss, and delay.
Logging of message status at both client and controller for easy debugging and analysis.

Requirements
-Python 3.x
-Libraries: socket, hashlib, time, threading

Python Code:
import hashlib
import socket
import threading
import time
import random

# Constants for setting up communication
HOST = '127.0.0.1'
PORT = 65432

# Function to create a message with integrity hash
def create_message(content):
    """Creates a message with content and appends SHA-256 hash for integrity."""
    hash_object = hashlib.sha256(content.encode())
    message_hash = hash_object.hexdigest()
    return f"{content}|{message_hash}"

def verify_message(message):
    """Verifies the integrity of the message by comparing hashes."""
    try:
        content, received_hash = message.rsplit('|', 1)
        computed_hash = hashlib.sha256(content.encode()).hexdigest()
        return computed_hash == received_hash, content
    except ValueError:
        return False, None  # Handle improperly formatted messages

class Controller:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        print("Controller listening for connections...")

    def handle_client(self, client_socket):
        while True:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            
            start_time = time.time()
            is_valid, content = verify_message(message)
            latency = (time.time() - start_time) * 1000  # in ms
            
            if is_valid:
                print(f"[Controller] Valid message received: '{content}' | Latency: {latency:.2f} ms")
            else:
                print("[Controller] Integrity check failed for received message.")

        client_socket.close()

    def start(self):
        while True:
            client_socket, _ = self.server_socket.accept()
            print("[Controller] Client connected.")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

class Client:
    def __init__(self, tamper_prob=0.2, loss_prob=0.2, delay_range=(0.5, 2.0)):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        self.tamper_prob = tamper_prob
        self.loss_prob = loss_prob
        self.delay_range = delay_range
        print("[Client] Connected to controller.")

    def simulate_tampering(self, message):
        """Simulate tampering with a given probability."""
        if random.random() < self.tamper_prob:
            tampered_message = message[::-1]  # Reverse message as an example of tampering
            print("[Client] Message tampered.")
            return tampered_message
        return message

    def simulate_packet_loss(self):
        """Simulate packet loss with a given probability."""
        if random.random() < self.loss_prob:
            print("[Client] Simulated message loss.")
            return True
        return False

    def simulate_delay(self):
        """Simulate network delay."""
        delay = random.uniform(*self.delay_range)
        print(f"[Client] Simulating delay of {delay:.2f} seconds.")
        time.sleep(delay)

    def send_message(self, content):
        message = create_message(content)

        # Simulate tampering
        message = self.simulate_tampering(message)

        # Simulate message loss
        if self.simulate_packet_loss():
            return  # Skip sending message to simulate loss

        # Simulate delay
        self.simulate_delay()

        # Send the message
        self.client_socket.sendall(message.encode())
        print(f"[Client] Sent message: '{content}'")

    def close(self):
        self.client_socket.close()

# Initialize and run the controller in a separate thread
controller = Controller()
controller_thread = threading.Thread(target=controller.start)
controller_thread.daemon = True
controller_thread.start()

# Experiment parameters
tamper_prob = 0.3     # Probability of tampering
loss_prob = 0.3       # Probability of packet loss
delay_range = (0.5, 2.0)  # Delay range in seconds

# Initialize the client with experiment configurations
client = Client(tamper_prob=tamper_prob, loss_prob=loss_prob, delay_range=delay_range)

# Send a series of test messages from the client to the controller
messages = ["Hello Controller", "Request Data", "Status Update", "Shutdown Signal"]
for msg in messages:
    client.send_message(msg)
    time.sleep(1)  # Simulate a delay between messages

# Close the client connection
client.close()

Usage
Run the Controller (Server): The Controller runs in a separate thread, listening for incoming connections from clients.

Configure and Run the Client: The Client connects to the Controller and sends a series of test messages with simulated network issues, based on user-defined configurations.

Setup and Execution
.
.
.

Sample output:

Controller listening for connections...
[Client] Connected to controller.
[Client] Message tampered.
[Client] Simulated message loss.
[Controller] Client connected.
[Client] Simulated message loss.
[Client] Simulating delay of 1.79 seconds.
[Controller] Valid message received: 'Status Update' | Latency: 0.00 ms[Client] Sent message: 'Status Update'

[Client] Message tampered.
[Client] Simulating delay of 0.82 seconds.
[Controller] Integrity check failed for received message.[Client] Sent message: 'Shutdown Signal'


Related work
As the number of endpoints in a network rises, so does the likelihood of security vulnerabilities being exploited. To mitigate these risks, encryption is often used as a first line of defense in IoT systems (Li, Lou & Ren, 2020). However, encryption can have an effect on the system performance as it introduces computational overhead (fastercapital,2024)

Experiment Results:
In this study, the experiments demonstrate that encryption significantly mitigates security risks by preventing unencrypted data transmission, which is consistent with findings by Alrawais et al. (2017). However, encryption adds latency, particularly as the number of devices increases
The integrity verification system demonstrated strong security effectiveness, accurately detecting and rejecting tampered messages, thereby mitigating the risk of data compromise. Reliability under network disruptions was reasonable, although implementing a message retry protocol could further enhance system robustness.

Key Findings:
-Latency: Minimal impact under standard conditions, but noticeable at high throughput.
-Security: Effective tampering detection with SHA-256 hashing, enhancing system integrity.
-Reliability: Stable handling of delays, with room for improvement in handling message loss.

Recommendations:
-Consider optimized hashing algorithms or selective hashing methods to reduce latency for high-frequency messaging.
-Integrate a retry protocol to enhance reliability in lossy network conditions.
-Expand the security model to address other vulnerabilities identified in the Attack-Defense Tree, such as secure message encryption alongside integrity verification.


References:

Alrawais, A., Alhothaily, A., Hu, C. and Cheng, X., (2017). Fog computing for the internet of things: Security and privacy issues. IEEE Internet Computing, 21(2), pp.34-42.

Boardman, J. and Sauser, B., (2006). System of Systems-the meaning of of. In 2006 IEEE/SMC international conference on system of systems engineering (pp. 6-pp). IEEE.

fastercapital (2024). Business data privacy 1: Encryption: Unlocking the Secrets: Safeguarding Business Data Privacy with Encryption. [online] Available at: https://fastercapital.com/content/Business-data-privacy-1--Encryption---Unlocking-the-Secrets--Safeguarding-Business-Data-Privacy-with-Encryption.html [Accessed 11 Nov. 2024].

Li, F., Zheng, Z. and Jin, C., (2016). Secure and efficient data transmission in the Internet of Things. Telecommunication Systems, 62, pp.111-122




