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