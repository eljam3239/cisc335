import socket
import struct

def build_dns_query(hostname):
    # DNS header fields
    ID = 0x1234  # Random ID
    FLAGS = 0x0100  # Standard query
    QDCOUNT = 1  # Number of questions
    ANCOUNT = 0  # Number of answers
    NSCOUNT = 0  # Number of authority records
    ARCOUNT = 0  # Number of additional records

    # Pack the header
    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Build the question section
    question = b''
    for part in hostname.split('.'):
        question += struct.pack('!B', len(part)) + part.encode()
    question += b'\x00'  # End of hostname
    question += struct.pack('!HH', 1, 1)  # Type A, Class IN

    return header + question

def parse_dns_response(response):
    # Unpack the header
    header = struct.unpack('!HHHHHH', response[:12])
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = header

    print(f"ID: {ID}, Flags: {FLAGS}, Questions: {QDCOUNT}, Answers: {ANCOUNT}, "
          f"Authority: {NSCOUNT}, Additional: {ARCOUNT}")

    # Parse the question section (skip for now)
    offset = 12
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte and QTYPE, QCLASS

    # Parse the answer section
    for _ in range(ANCOUNT):
        # Extract name, type, class, TTL, and data length
        name = response[offset:offset+2]
        offset += 2
        type_, class_, ttl, data_len = struct.unpack('!HHIH', response[offset:offset+10])
        offset += 10
        if type_ == 1:  # Type A record
            ip = socket.inet_ntoa(response[offset:offset+4])
            print(f"Answer: {ip}")
        offset += data_len

def main():
    hostname = input("Enter hostname: ")
    dns_query = build_dns_query(hostname)

    # Send the query to a local DNS server (e.g., Google's public DNS)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)  # Set timeout for response
    sock.sendto(dns_query, ('8.8.8.8', 53))  # Send to Google's DNS server

    # Receive the response
    try:
        response, _ = sock.recvfrom(512)  # Max DNS response size
        parse_dns_response(response)
    except socket.timeout:
        print("Request timed out")
    finally:
        sock.close()

if __name__ == "__main__":
    main()