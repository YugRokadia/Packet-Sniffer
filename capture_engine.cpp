#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <map>
#include <string>

using namespace std;

// Connection tracking: maps TCP connection to SNI domain
// Key format: "src_ip:src_port->dst_ip:dst_port"
map<string, string> connection_to_domain;

// Helper function to create connection key
string make_connection_key(const string& src_ip, int src_port, const string& dst_ip, int dst_port) {
    stringstream ss;
    ss << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
    return ss.str();
}

// Helper function to lookup domain for a connection (checks both directions)
string lookup_domain(const string& src_ip, int src_port, const string& dst_ip, int dst_port) {
    string forward_key = make_connection_key(src_ip, src_port, dst_ip, dst_port);
    string reverse_key = make_connection_key(dst_ip, dst_port, src_ip, src_port);
    
    if (connection_to_domain.count(forward_key)) {
        return connection_to_domain[forward_key];
    }
    if (connection_to_domain.count(reverse_key)) {
        return connection_to_domain[reverse_key];
    }
    return "";
}

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};

// Parse DNS query name from DNS packet
// Returns the domain name extracted from DNS question section
string parse_dns_query(const u_char *dns_payload, int payload_len) {
    if (payload_len < (int)sizeof(dns_header) + 5) {
        return "";  // Too small for valid DNS query
    }
    
    const dns_header *dns_hdr = (const dns_header *)dns_payload;
    uint16_t question_count = ntohs(dns_hdr->qdcount);
    
    if (question_count == 0) {
        return "";  // No questions in this packet (likely a response)
    }
    
    // Start parsing the question name after the DNS header
    const u_char *name_ptr = dns_payload + sizeof(dns_header);
    const u_char *payload_end = dns_payload + payload_len;
    stringstream domain;
    
    // Parse DNS name format (length-prefixed labels)
    while (name_ptr < payload_end) {
        uint8_t label_len = *name_ptr;
        
        if (label_len == 0) {
            break;  // End of domain name
        }
        
        if (label_len > 63) {
            return "";  // Invalid label length or pointer (compression)
        }
        
        name_ptr++;
        
        if (name_ptr + label_len > payload_end) {
            return "";  // Label extends beyond packet
        }
        
        if (domain.tellp() > 0) {
            domain << ".";
        }
        
        domain.write((const char *)name_ptr, label_len);
        name_ptr += label_len;
    }
    
    return domain.str();
}

// Parse SNI (Server Name Indication) from TLS ClientHello
// Returns the domain name from HTTPS handshake
string parse_tls_sni(const u_char *tcp_payload, int payload_len) {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if (payload_len < 43) return "";  // Minimum size for ClientHello with SNI
    
    // Check if this is a TLS handshake (content type = 0x16)
    if (tcp_payload[0] != 0x16) return "";
    
    // Check TLS version (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
    if (tcp_payload[1] != 0x03) return "";
    
    // Skip TLS record header (5 bytes)
    const u_char *handshake = tcp_payload + 5;
    int handshake_len = payload_len - 5;
    
    if (handshake_len < 38) return "";
    
    // Check if this is ClientHello (handshake type = 0x01)
    if (handshake[0] != 0x01) return "";
    
    // Skip: handshake_type(1) + length(3) + version(2) + random(32) = 38 bytes
    const u_char *session_id_len_ptr = handshake + 38;
    if (session_id_len_ptr >= tcp_payload + payload_len) return "";
    
    uint8_t session_id_len = *session_id_len_ptr;
    const u_char *ptr = session_id_len_ptr + 1 + session_id_len;
    
    // Skip cipher suites
    if (ptr + 2 > tcp_payload + payload_len) return "";
    uint16_t cipher_suites_len = (ptr[0] << 8) | ptr[1];
    ptr += 2 + cipher_suites_len;
    
    // Skip compression methods
    if (ptr + 1 > tcp_payload + payload_len) return "";
    uint8_t compression_len = *ptr;
    ptr += 1 + compression_len;
    
    // Extensions length
    if (ptr + 2 > tcp_payload + payload_len) return "";
    uint16_t extensions_len = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    
    const u_char *extensions_end = ptr + extensions_len;
    if (extensions_end > tcp_payload + payload_len) return "";
    
    // Parse extensions to find SNI (type = 0x0000)
    while (ptr + 4 <= extensions_end) {
        uint16_t ext_type = (ptr[0] << 8) | ptr[1];
        uint16_t ext_len = (ptr[2] << 8) | ptr[3];
        ptr += 4;
        
        if (ptr + ext_len > extensions_end) return "";
        
        if (ext_type == 0x0000) {  // SNI extension
            const u_char *sni_ptr = ptr;
            if (sni_ptr + 2 > ptr + ext_len) return "";
            
            // uint16_t sni_list_len = (sni_ptr[0] << 8) | sni_ptr[1];  // Not used
            sni_ptr += 2;
            
            if (sni_ptr + 3 > ptr + ext_len) return "";
            
            uint8_t sni_type = sni_ptr[0];  // Should be 0x00 for host_name
            uint16_t sni_len = (sni_ptr[1] << 8) | sni_ptr[2];
            sni_ptr += 3;
            
            if (sni_type == 0x00 && sni_ptr + sni_len <= ptr + ext_len) {
                return string((const char *)sni_ptr, sni_len);
            }
        }
        
        ptr += ext_len;
    }
    
    return "";
}

// Callback function called by pcap_loop for each captured packet
// Outputs packet metadata in JSON format for Python processing
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    // Check if packet is large enough for Ethernet header
    if (header->len < 14) {
        return; // Skip malformed packets
    }

    // Extract Ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_hdr->ether_type);

    // Prepare JSON output
    cout << "{";
    cout << "\"timestamp\":" << header->ts.tv_sec << "." << header->ts.tv_usec << ",";
    cout << "\"length\":" << header->len << ",";

    // Handle different Ethernet types
    if (ether_type == ETHERTYPE_IP) {
        // IPv4 packet
        const struct ip *ip_hdr = (struct ip *)(packet + 14);
        char src_ip_buf[INET_ADDRSTRLEN];
        char dst_ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip_buf, INET_ADDRSTRLEN);
        string src_ip(src_ip_buf);
        string dst_ip(dst_ip_buf);
        int protocol = ip_hdr->ip_p;
        string proto_name;

        // Get IP header length in bytes
        unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

        cout << "\"src_ip\":\"" << src_ip << "\",";
        cout << "\"dst_ip\":\"" << dst_ip << "\",";

        // Identify protocol type and extract port numbers
        if (protocol == IPPROTO_TCP) {
            if (header->len < 14 + ip_hdr_len + 20) return; // TCP header min 20 bytes
            const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr_len);
            uint16_t src_port = ntohs(tcp_hdr->th_sport);
            uint16_t dst_port = ntohs(tcp_hdr->th_dport);
            bool is_closing = (tcp_hdr->th_flags & TH_FIN) || (tcp_hdr->th_flags & TH_RST);
            
            // Identify application layer protocol based on well-known ports
            if (src_port == 80 || dst_port == 80) {
                proto_name = "HTTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 443 || dst_port == 443) {
                proto_name = "HTTPS";
                
                // Try to extract SNI from TLS ClientHello
                unsigned int tcp_hdr_len = tcp_hdr->th_off * 4;  // TCP header length in bytes
                unsigned int headers_len = 14 + ip_hdr_len + tcp_hdr_len;
                
                string domain;
                
                if (header->len > headers_len) {
                    const u_char *tcp_payload = packet + headers_len;
                    int tcp_payload_len = header->len - headers_len;
                    string sni = parse_tls_sni(tcp_payload, tcp_payload_len);
                    
                    if (!sni.empty()) {
                        // Store this connection -> domain mapping
                        string conn_key = make_connection_key(src_ip, src_port, dst_ip, dst_port);
                        connection_to_domain[conn_key] = sni;
                        domain = sni;
                    } else {
                        // Look up domain from connection tracking
                        domain = lookup_domain(src_ip, src_port, dst_ip, dst_port);
                    }
                } else {
                    // Look up domain from connection tracking
                    domain = lookup_domain(src_ip, src_port, dst_ip, dst_port);
                }
                
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
                if (!domain.empty()) {
                    cout << ",\"domain\":\"" << domain << "\"";
                }
            } else if (src_port == 22 || dst_port == 22) {
                proto_name = "SSH";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 21 || dst_port == 21) {
                proto_name = "FTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 25 || dst_port == 25) {
                proto_name = "SMTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 110 || dst_port == 110) {
                proto_name = "POP3";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 143 || dst_port == 143) {
                proto_name = "IMAP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 3306 || dst_port == 3306) {
                proto_name = "MySQL";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 5432 || dst_port == 5432) {
                proto_name = "PostgreSQL";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 3389 || dst_port == 3389) {
                proto_name = "RDP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else {
                proto_name = "TCP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            }
            
            // Clean up closed connections after outputting packet (preserves domain in final packet)
            if (is_closing) {
                string conn_key = make_connection_key(src_ip, src_port, dst_ip, dst_port);
                connection_to_domain.erase(conn_key);
                string reverse_key = make_connection_key(dst_ip, dst_port, src_ip, src_port);
                connection_to_domain.erase(reverse_key);
            }
        } else if (protocol == IPPROTO_UDP) {
            if (header->len < 14 + ip_hdr_len + 8) return; // UDP header = 8 bytes
            const struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + ip_hdr_len);
            uint16_t src_port = ntohs(udp_hdr->uh_sport);
            uint16_t dst_port = ntohs(udp_hdr->uh_dport);
            uint16_t udp_len = ntohs(udp_hdr->uh_ulen);
            
            // Validate UDP length
            if (udp_len < 8 || udp_len > header->len - (14 + ip_hdr_len)) return;
            
            // Identify application layer protocol based on well-known ports
            if (src_port == 53 || dst_port == 53) {
                proto_name = "DNS";
                
                // Parse DNS query only (not responses)
                if (dst_port == 53) {
                    int udp_header_len = 8;
                    const u_char *dns_payload = packet + 14 + ip_hdr_len + udp_header_len;
                    int dns_payload_len = udp_len - udp_header_len;
                
                    if (dns_payload_len > 0) {
                        string domain = parse_dns_query(dns_payload, dns_payload_len);
                        if (!domain.empty()) {
                            cout << "\"protocol\":\"" << proto_name << "\",";
                            cout << "\"src_port\":" << src_port << ",";
                            cout << "\"dst_port\":" << dst_port << ",";
                            cout << "\"dns_query\":\"" << domain << "\"";
                        } else {
                            cout << "\"protocol\":\"" << proto_name << "\",";
                            cout << "\"src_port\":" << src_port << ",";
                            cout << "\"dst_port\":" << dst_port;
                        }
                    } else {
                        cout << "\"protocol\":\"" << proto_name << "\",";
                        cout << "\"src_port\":" << src_port << ",";
                        cout << "\"dst_port\":" << dst_port;
                    }
                } else {
                    // DNS response, no query to parse
                    cout << "\"protocol\":\"" << proto_name << "\",";
                    cout << "\"src_port\":" << src_port << ",";
                    cout << "\"dst_port\":" << dst_port;
                }
            } else if (src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68) {
                proto_name = "DHCP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 123 || dst_port == 123) {
                proto_name = "NTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 161 || dst_port == 161 || src_port == 162 || dst_port == 162) {
                proto_name = "SNMP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 1900 || dst_port == 1900) {
                proto_name = "SSDP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else {
                proto_name = "UDP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            }
        } else if (protocol == IPPROTO_ICMP) {
            cout << "\"protocol\":\"ICMP\"";
        } else {
            cout << "\"protocol\":\"IPv4-Other\",";
            cout << "\"ip_proto\":" << protocol;
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        // IPv6 packet
        const struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(packet + 14);
        char src_ip_buf[INET6_ADDRSTRLEN];
        char dst_ip_buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6_hdr->ip6_src), src_ip_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_hdr->ip6_dst), dst_ip_buf, INET6_ADDRSTRLEN);
        string src_ip(src_ip_buf);  // Convert to string once
        string dst_ip(dst_ip_buf);
        
        int next_header = ipv6_hdr->ip6_nxt;
        string proto_name;
        unsigned int ipv6_offset = 54; // Ethernet (14) + IPv6 header (40)
        
        // Handle IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Destination Options)
        while (next_header == 0 || next_header == 43 || next_header == 44 || next_header == 60) {
            if (header->len < ipv6_offset + 2) return; // Need at least 2 bytes for next header + length
            const u_char *ext_hdr = packet + ipv6_offset;
            next_header = ext_hdr[0]; // Next header type
            uint8_t ext_len = ext_hdr[1]; // Extension header length (in 8-byte units, excluding first 8 bytes)
            ipv6_offset += (ext_len + 1) * 8; // Skip extension header
            if (ipv6_offset > header->len) return; // Extension extends beyond packet
        }
        
        cout << "\"src_ip\":\"" << src_ip << "\",";
        cout << "\"dst_ip\":\"" << dst_ip << "\",";
        
        // Parse transport layer for IPv6
        if (next_header == IPPROTO_TCP) {
            if (header->len < ipv6_offset + 20) return; // TCP header min 20 bytes
            const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ipv6_offset);
            uint16_t src_port = ntohs(tcp_hdr->th_sport);
            uint16_t dst_port = ntohs(tcp_hdr->th_dport);
            bool is_closing = (tcp_hdr->th_flags & TH_FIN) || (tcp_hdr->th_flags & TH_RST);
            
            // Identify application layer protocol
            if (src_port == 80 || dst_port == 80) {
                proto_name = "HTTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 443 || dst_port == 443) {
                proto_name = "HTTPS";
                
                // Try to extract SNI from TLS ClientHello
                unsigned int tcp_hdr_len = tcp_hdr->th_off * 4;  // TCP header length in bytes
                unsigned int headers_len = ipv6_offset + tcp_hdr_len;
                
                string domain;
                
                if (header->len > headers_len) {
                    const u_char *tcp_payload = packet + headers_len;
                    int tcp_payload_len = header->len - headers_len;
                    string sni = parse_tls_sni(tcp_payload, tcp_payload_len);
                    
                    if (!sni.empty()) {
                        // Store this connection -> domain mapping
                        string conn_key = make_connection_key(src_ip, src_port, dst_ip, dst_port);
                        connection_to_domain[conn_key] = sni;
                        domain = sni;
                    } else {
                        // Look up domain from connection tracking
                        domain = lookup_domain(src_ip, src_port, dst_ip, dst_port);
                    }
                } else {
                    // Look up domain from connection tracking
                    domain = lookup_domain(src_ip, src_port, dst_ip, dst_port);
                }
                
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
                if (!domain.empty()) {
                    cout << ",\"domain\":\"" << domain << "\"";
                }
            } else if (src_port == 22 || dst_port == 22) {
                proto_name = "SSH";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else {
                proto_name = "TCP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            }
            
            // Clean up closed connections after outputting packet (preserves domain in final packet)
            if (is_closing) {
                string conn_key = make_connection_key(src_ip, src_port, dst_ip, dst_port);
                connection_to_domain.erase(conn_key);
                string reverse_key = make_connection_key(dst_ip, dst_port, src_ip, src_port);
                connection_to_domain.erase(reverse_key);
            }
        } else if (next_header == IPPROTO_UDP) {
            if (header->len < ipv6_offset + 8) return; // UDP header = 8 bytes
            const struct udphdr *udp_hdr = (struct udphdr *)(packet + ipv6_offset);
            uint16_t src_port = ntohs(udp_hdr->uh_sport);
            uint16_t dst_port = ntohs(udp_hdr->uh_dport);
            uint16_t udp_len = ntohs(udp_hdr->uh_ulen);
            
            // Validate UDP length
            if (udp_len < 8 || udp_len > header->len - ipv6_offset) return;
            
            // Identify application layer protocol
            if (src_port == 53 || dst_port == 53) {
                proto_name = "DNS";
                
                // Parse DNS query only (not responses)
                if (dst_port == 53) {
                    int udp_header_len = 8;
                    const u_char *dns_payload = packet + ipv6_offset + udp_header_len;
                    int dns_payload_len = udp_len - udp_header_len;
                
                    if (dns_payload_len > 0) {
                        string domain = parse_dns_query(dns_payload, dns_payload_len);
                        if (!domain.empty()) {
                            cout << "\"protocol\":\"" << proto_name << "\",";
                            cout << "\"src_port\":" << src_port << ",";
                            cout << "\"dst_port\":" << dst_port << ",";
                            cout << "\"dns_query\":\"" << domain << "\"";
                        } else {
                            cout << "\"protocol\":\"" << proto_name << "\",";
                            cout << "\"src_port\":" << src_port << ",";
                            cout << "\"dst_port\":" << dst_port;
                        }
                    } else {
                        cout << "\"protocol\":\"" << proto_name << "\",";
                        cout << "\"src_port\":" << src_port << ",";
                        cout << "\"dst_port\":" << dst_port;
                    }
                } else {
                    // DNS response, no query to parse
                    cout << "\"protocol\":\"" << proto_name << "\",";
                    cout << "\"src_port\":" << src_port << ",";
                    cout << "\"dst_port\":" << dst_port;
                }
            } else if (src_port == 123 || dst_port == 123) {
                proto_name = "NTP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else if (src_port == 1900 || dst_port == 1900) {
                proto_name = "SSDP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            } else {
                proto_name = "UDP";
                cout << "\"protocol\":\"" << proto_name << "\",";
                cout << "\"src_port\":" << src_port << ",";
                cout << "\"dst_port\":" << dst_port;
            }
        } else if (next_header == IPPROTO_ICMPV6) {
            cout << "\"protocol\":\"ICMPv6\"";
        } else {
            cout << "\"protocol\":\"IPv6-Other\",";
            cout << "\"next_header\":" << next_header;
        }
    } else if (ether_type == ETHERTYPE_ARP) {
        // ARP packet
        cout << "\"protocol\":\"ARP\"";
    } else {
        // Unknown protocol
        cout << "\"protocol\":\"Unknown\",";
        cout << "\"ether_type\":\"0x" << hex << ether_type << dec << "\"";
    }

    cout << "}" << endl;
    cout.flush(); // Ensure immediate output for Python to read
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
    cout.flush();
    // Start continuous capture loop (0 = infinite packets)
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle); // Close the capture handle
    return 0;
}
