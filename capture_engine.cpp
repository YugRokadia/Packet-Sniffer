#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>

using namespace std;

// Callback function called by pcap_loop for each captured packet
// Prints packet metadata: timestamp, source/destination IP, protocol, and length
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Check if packet is large enough for Ethernet header
    if (header->len < 14) {
        return; // Skip malformed packets
    }

    // Extract Ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    // Handle different Ethernet types
    if (ether_type == ETHERTYPE_IP) {
        // IPv4 packet
        const struct ip *ip_hdr = (struct ip *)(packet + 14);
        string src_ip = inet_ntoa(ip_hdr->ip_src);
        string dst_ip = inet_ntoa(ip_hdr->ip_dst);
        int protocol = ip_hdr->ip_p;
        string proto_name;
        string port_info = "";

        // Get IP header length in bytes
        int ip_hdr_len = ip_hdr->ip_hl * 4;

        // Identify protocol type and extract port numbers
        if (protocol == IPPROTO_TCP) {
            const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr_len);
            uint16_t src_port = ntohs(tcp_hdr->th_sport);
            uint16_t dst_port = ntohs(tcp_hdr->th_dport);
            
            // Identify application layer protocol based on well-known ports
            if (src_port == 80 || dst_port == 80) {
                proto_name = "HTTP";
            } else if (src_port == 443 || dst_port == 443) {
                proto_name = "HTTPS";
            } else if (src_port == 22 || dst_port == 22) {
                proto_name = "SSH";
            } else if (src_port == 21 || dst_port == 21) {
                proto_name = "FTP";
            } else if (src_port == 25 || dst_port == 25) {
                proto_name = "SMTP";
            } else if (src_port == 110 || dst_port == 110) {
                proto_name = "POP3";
            } else if (src_port == 143 || dst_port == 143) {
                proto_name = "IMAP";
            } else if (src_port == 3306 || dst_port == 3306) {
                proto_name = "MySQL";
            } else if (src_port == 5432 || dst_port == 5432) {
                proto_name = "PostgreSQL";
            } else if (src_port == 3389 || dst_port == 3389) {
                proto_name = "RDP";
            } else {
                proto_name = "TCP";
            }
            port_info = " | Ports: " + to_string(src_port) + " -> " + to_string(dst_port);
        } else if (protocol == IPPROTO_UDP) {
            const struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + ip_hdr_len);
            uint16_t src_port = ntohs(udp_hdr->uh_sport);
            uint16_t dst_port = ntohs(udp_hdr->uh_dport);
            
            // Identify application layer protocol based on well-known ports
            if (src_port == 53 || dst_port == 53) {
                proto_name = "DNS";
            } else if (src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68) {
                proto_name = "DHCP";
            } else if (src_port == 123 || dst_port == 123) {
                proto_name = "NTP";
            } else if (src_port == 161 || dst_port == 161 || src_port == 162 || dst_port == 162) {
                proto_name = "SNMP";
            } else {
                proto_name = "UDP";
            }
            port_info = " | Ports: " + to_string(src_port) + " -> " + to_string(dst_port);
        } else if (protocol == IPPROTO_ICMP) {
            proto_name = "ICMP";
        } else {
            proto_name = "IPv4-Other(" + to_string(protocol) + ")";
        }

        // Print packet metadata
        cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec
             << " | Src: " << src_ip
             << " | Dst: " << dst_ip
             << " | Proto: " << proto_name
             << port_info
             << " | Length: " << header->len << endl;
    } else if (ether_type == ETHERTYPE_IPV6) {
        // IPv6 packet
        cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec
             << " | Proto: IPv6 | Length: " << header->len << endl;
    } else if (ether_type == ETHERTYPE_ARP) {
        // ARP packet
        cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec
             << " | Proto: ARP | Length: " << header->len << endl;
    } else {
        // Unknown protocol
        cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec
             << " | Proto: Unknown(0x" << hex << ether_type << dec << ") | Length: " << header->len << endl;
    }
}

// Main function: sets up packet capture and starts the capture loop
int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    const char *dev = nullptr;
    string dev_name; // Store device name safely

    // Select network device to capture on
    if (argc > 1) {
        dev = argv[1]; // Use device from command line argument
    } else {
        // List all available devices using pcap_findalldevs
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            cerr << "Error finding devices: " << errbuf << endl;
            return 1;
        }
        cout << "Available network interfaces:" << endl;
        int i = 0;
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            cout << "  [" << i << "] " << d->name;
            if (d->description) cout << " - " << d->description;
            cout << endl;
            ++i;
        }
        if (i == 0) {
            cerr << "No interfaces found. Exiting." << endl;
            pcap_freealldevs(alldevs);
            return 1;
        }
        cout << "Enter interface number to use: ";
        int choice = 0;
        cin >> choice;
        if (choice < 0 || choice >= i) {
            cerr << "Invalid choice." << endl;
            pcap_freealldevs(alldevs);
            return 1;
        }
        pcap_if_t *selected = alldevs;
        for (int j = 0; j < choice; ++j) selected = selected->next;
        dev_name = selected->name; // Copy device name before freeing
        pcap_freealldevs(alldevs);
        dev = dev_name.c_str();
    }

    // Open the device for live capture
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        return 1;
    }

    cout << "Capturing on device: " << dev << endl;
    // Start capture loop: capture 10 packets and call packet_handler for each
    pcap_loop(handle, 10, packet_handler, nullptr); // Capture 10 packets for test
    pcap_close(handle); // Close the capture handle
    return 0;
}
