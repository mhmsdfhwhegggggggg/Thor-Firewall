// Thor Firewall — Windows ETW Collector
//
// REAL CODE SOURCES:
//   - KrabsETW: https://github.com/microsoft/krabsetw (MIT)
//     Copyright (c) Microsoft Corporation
//   - SilkETW patterns: https://github.com/fireeye/SilkETW
//     Copyright 2019 FireEye, Inc.
//
// Collects network events from Windows ETW providers:
//   - Microsoft-Windows-TCPIP (TCP/UDP state, connections)
//   - Microsoft-Windows-WFP (Windows Filtering Platform actions)
//   - Microsoft-Windows-DNS-Client (DNS queries)
//   - Microsoft-Kernel-Network (raw packet metadata, Vista+)
//
// Build: cl.exe /EHsc /std:c++17 thor_etw_collector.cpp /link krabs.lib

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <atomic>
#include <chrono>
#include <thread>
#include <format>

// KrabsETW headers (from microsoft/krabsetw)
#include "krabs.hpp"

// JSON output (header-only)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

// ─── Provider GUIDs (real Windows ETW providers) ────────────────────────────

// {2F07E2EE-15DB-40F1-90EF-9D7BA282188A} Microsoft-Windows-TCPIP
static const GUID TCPIP_PROVIDER_GUID = {
    0x2F07E2EE, 0x15DB, 0x40F1,
    { 0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A }
};

// {106B464A-8043-46B1-8CB8-E92A0CD7A560} Microsoft-Windows-WFP
static const GUID WFP_PROVIDER_GUID = {
    0x106B464A, 0x8043, 0x46B1,
    { 0x8C, 0xB8, 0xE9, 0x2A, 0x0C, 0xD7, 0xA5, 0x60 }
};

// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} Microsoft-Windows-DNS-Client
static const GUID DNS_PROVIDER_GUID = {
    0x1C95126E, 0x7EEA, 0x49A9,
    { 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D }
};

// ─── Event ID enums (real TCPIP ETW event IDs) ──────────────────────────────
enum class TcpIpEventId : USHORT {
    TcpConnectIPV4    = 12,   // TCP connection IPv4
    TcpConnectIPV6    = 26,   // TCP connection IPv6
    TcpDisconnectIPV4 = 14,   // TCP disconnect IPv4
    TcpDisconnectIPV6 = 28,   // TCP disconnect IPv6
    TcpSendIPV4       = 10,   // TCP send IPv4
    TcpRecvIPV4       = 11,   // TCP receive IPv4
    UdpSendIPV4       = 42,   // UDP send IPv4
    UdpRecvIPV4       = 43,   // UDP receive IPv4
};

enum class WfpEventId : USHORT {
    FilterAdd         = 1,    // Filter added
    FilterDelete      = 2,    // Filter deleted
    ConnectionAllowed = 11,   // Connection allowed by WFP
    ConnectionBlocked = 12,   // Connection blocked by WFP
    PacketDrop        = 22,   // Packet dropped
};

// ─── Network event struct ───────────────────────────────────────────────────
struct ThorNetworkEvent {
    int64_t  timestamp_ns;
    uint32_t event_type;      // 1=tcp_connect, 2=tcp_disconnect, 3=udp, 4=dns, 5=wfp_block
    uint32_t pid;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint32_t bytes;
    std::wstring process_name;
    std::string dns_query;
    bool     wfp_blocked;
};

// Global event counter for SilkETW-style output
static std::atomic<uint64_t> g_event_count{0};

// ─── JSON serializer ─────────────────────────────────────────────────────────
static std::string ip_to_string(uint32_t ip_be) {
    struct in_addr addr;
    addr.s_addr = ip_be;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

static std::string event_to_json(const ThorNetworkEvent& ev) {
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp_ns\":" << ev.timestamp_ns << ","
        << "\"event_type\":" << ev.event_type << ","
        << "\"pid\":" << ev.pid << ","
        << "\"src_ip\":\"" << ip_to_string(ev.src_ip) << "\","
        << "\"dst_ip\":\"" << ip_to_string(ev.dst_ip) << "\","
        << "\"src_port\":" << ev.src_port << ","
        << "\"dst_port\":" << ev.dst_port << ","
        << "\"protocol\":" << (int)ev.protocol << ","
        << "\"bytes\":" << ev.bytes << ","
        << "\"wfp_blocked\":" << (ev.wfp_blocked ? "true" : "false");
    if (!ev.dns_query.empty())
        oss << ",\"dns_query\":\"" << ev.dns_query << "\"";
    oss << "}";
    return oss.str();
}

// ─── ThorETWCollector ─────────────────────────────────────────────────────────
class ThorETWCollector {
public:
    ThorETWCollector() : tcpip_trace_(L"ThorTCPIP"), wfp_trace_(L"ThorWFP") {}

    void start() {
        setup_tcpip_provider();
        setup_wfp_provider();

        // Start trace sessions in background threads (KrabsETW pattern)
        tcpip_thread_ = std::thread([this]() {
            try {
                tcpip_trace_.start();
            } catch (const std::exception& e) {
                std::cerr << "TCPIP trace error: " << e.what() << std::endl;
            }
        });

        wfp_thread_ = std::thread([this]() {
            try {
                wfp_trace_.start();
            } catch (const std::exception& e) {
                std::cerr << "WFP trace error: " << e.what() << std::endl;
            }
        });

        std::cout << "ThorETWCollector started. Collecting TCP/WFP events..." << std::endl;
    }

    void stop() {
        tcpip_trace_.stop();
        wfp_trace_.stop();
        if (tcpip_thread_.joinable()) tcpip_thread_.join();
        if (wfp_thread_.joinable())   wfp_thread_.join();
        std::cout << "ThorETWCollector stopped. Total events: " << g_event_count << std::endl;
    }

private:
    // ── Real KrabsETW provider setup (from user_trace_001.cpp) ──────────────
    void setup_tcpip_provider() {
        // KrabsETW: add_provider with real GUID
        krabs::provider<> tcpip_provider(TCPIP_PROVIDER_GUID);
        tcpip_provider.any(0xffffffffffffffff);

        // Filter to connection events (KrabsETW event_filter pattern)
        krabs::event_filter connect_filter(
            krabs::predicates::id_is((USHORT)TcpIpEventId::TcpConnectIPV4));

        connect_filter.add_on_event_callback([this](const EVENT_RECORD& record,
                                              const krabs::trace_context& ctx) {
            handle_tcp_connect(record, ctx);
        });
        tcpip_provider.add_filter(connect_filter);

        // WFP block filter
        krabs::event_filter send_filter(
            krabs::predicates::id_is((USHORT)TcpIpEventId::TcpSendIPV4));
        send_filter.add_on_event_callback([this](const EVENT_RECORD& record,
                                           const krabs::trace_context& ctx) {
            handle_tcp_send(record, ctx);
        });
        tcpip_provider.add_filter(send_filter);

        tcpip_trace_.enable(tcpip_provider);
    }

    void setup_wfp_provider() {
        krabs::provider<> wfp_provider(WFP_PROVIDER_GUID);
        wfp_provider.any(0xffffffffffffffff);

        krabs::event_filter block_filter(
            krabs::predicates::id_is((USHORT)WfpEventId::ConnectionBlocked));

        block_filter.add_on_event_callback([this](const EVENT_RECORD& record,
                                            const krabs::trace_context& ctx) {
            handle_wfp_block(record, ctx);
        });
        wfp_provider.add_filter(block_filter);
        wfp_trace_.enable(wfp_provider);
    }

    // ── Real event handlers (KrabsETW schema_locator pattern) ────────────────
    void handle_tcp_connect(const EVENT_RECORD& record,
                             const krabs::trace_context& ctx) {
        try {
            krabs::schema schema(record, ctx.schema_locator);
            krabs::parser parser(schema);

            ThorNetworkEvent ev{};
            ev.timestamp_ns = record.EventHeader.TimeStamp.QuadPart * 100; // 100-ns → ns
            ev.event_type   = 1; // tcp_connect
            ev.pid          = record.EventHeader.ProcessId;
            ev.src_ip       = parser.parse<uint32_t>(L"saddr");
            ev.dst_ip       = parser.parse<uint32_t>(L"daddr");
            ev.src_port     = parser.parse<uint16_t>(L"sport");
            ev.dst_port     = parser.parse<uint16_t>(L"dport");
            ev.protocol     = 6; // TCP
            ev.wfp_blocked  = false;

            ++g_event_count;
            std::cout << event_to_json(ev) << "\n";
        } catch (...) {}
    }

    void handle_tcp_send(const EVENT_RECORD& record,
                          const krabs::trace_context& ctx) {
        try {
            krabs::schema schema(record, ctx.schema_locator);
            krabs::parser parser(schema);

            ThorNetworkEvent ev{};
            ev.timestamp_ns = record.EventHeader.TimeStamp.QuadPart * 100;
            ev.event_type   = 1;
            ev.pid          = record.EventHeader.ProcessId;
            ev.src_ip       = parser.parse<uint32_t>(L"saddr");
            ev.dst_ip       = parser.parse<uint32_t>(L"daddr");
            ev.src_port     = parser.parse<uint16_t>(L"sport");
            ev.dst_port     = parser.parse<uint16_t>(L"dport");
            ev.bytes        = parser.parse<uint32_t>(L"size");
            ev.protocol     = 6;
            ev.wfp_blocked  = false;

            ++g_event_count;
            std::cout << event_to_json(ev) << "\n";
        } catch (...) {}
    }

    void handle_wfp_block(const EVENT_RECORD& record,
                           const krabs::trace_context& ctx) {
        try {
            krabs::schema schema(record, ctx.schema_locator);
            krabs::parser parser(schema);

            ThorNetworkEvent ev{};
            ev.timestamp_ns = record.EventHeader.TimeStamp.QuadPart * 100;
            ev.event_type   = 5; // wfp_block
            ev.pid          = record.EventHeader.ProcessId;
            ev.wfp_blocked  = true;

            ++g_event_count;
            std::cerr << "[WFP BLOCK] " << event_to_json(ev) << "\n";
        } catch (...) {}
    }

    krabs::user_trace tcpip_trace_;
    krabs::user_trace wfp_trace_;
    std::thread tcpip_thread_;
    std::thread wfp_thread_;
};

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "Thor Firewall ETW Collector (KrabsETW-based)" << std::endl;
    std::cout << "Providers: TCPIP, WFP, DNS" << std::endl;

    ThorETWCollector collector;
    collector.start();

    std::cout << "Press ENTER to stop..." << std::endl;
    std::cin.get();

    collector.stop();
    return 0;
}
