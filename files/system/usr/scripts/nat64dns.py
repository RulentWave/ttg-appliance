import asyncio
import ipaddress
from typing import Optional

import netifaces
from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSHeader, DNSRecord

# Configuration
INTERFACE_NAME = "tailscale0"
LISTEN_PORT = 53
NAT64_SUFFIX = "nat64"
BASE_PREFIX = "64:ff9b:1::"
NAT64_PREFIX_FILE = "/etc/tayga/default.conf"
UPSTREAM_DNS = "127.0.0.53"
UPSTREAM_PORT = 53


def get_interface_ipv6_addrs(iface_name):
    """
    Returns a list of IPv6 addresses assigned to the specific interface.
    """
    try:
        if iface_name not in netifaces.interfaces():
            print(f"Interface {iface_name} not found.")
            return []

        addrs = netifaces.ifaddresses(iface_name)
        # AF_INET6 is usually integer 10 or 30 depending on OS, netifaces handles this
        if netifaces.AF_INET6 in addrs:
            # Extract just the IP strings, removing scope IDs (e.g. %tailscale0) if present
            return [x["addr"].split("%")[0] for x in addrs[netifaces.AF_INET6]]
        return []
    except Exception as e:
        print(f"Error getting addresses for {iface_name}: {e}")
        return []


class UpstreamClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, query_data, future):
        self.query_data = query_data
        self.future = future
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.query_data)

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.future.done():
            if exc:
                self.future.set_exception(exc)
            else:
                self.future.set_exception(ConnectionError("Connection closed"))


async def query_upstream_async(query_data, upstream_ip, upstream_port):
    """
    Sends a raw DNS query to upstream asynchronously and awaits the response.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    try:
        # Create a temporary UDP connection for this specific query
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UpstreamClientProtocol(query_data, future),
            remote_addr=(upstream_ip, upstream_port),
        )

        # Wait for result with a timeout
        try:
            data = await asyncio.wait_for(future, timeout=2.0)
            return data
        except asyncio.TimeoutError:
            transport.close()
            return None
    except Exception as e:
        print(f"Async upstream query error: {e}")
        return None


async def load_nat64_prefix_async():
    """
    Reads the NAT64 prefix from the file system.
    Runs in a thread executor to avoid blocking the event loop with file I/O.
    """
    loop = asyncio.get_running_loop()

    def _read_and_parse():
        try:
            with open(NAT64_PREFIX_FILE, "r") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("prefix"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
            return None

        except FileNotFoundError:
            # File doesn't exist, just return None
            return None
        except Exception as e:
            print(f"Error reading {NAT64_PREFIX_FILE}: {e}")
            return None

    # Run the file IO and string parsing in the thread
    ipv6_prefix_str = await loop.run_in_executor(None, _read_and_parse)

    if not ipv6_prefix_str:
        return None

    try:
        # Validate the IP object back in the main thread
        return ipaddress.IPv6Network(ipv6_prefix_str, strict=False)
    except ValueError:
        print(f"Invalid IPv6 prefix format: {ipv6_prefix_str}")
        return None


class NAT64Resolver:
    def parse(self, qname_str):
        """
        Parses the query name and returns a tuple of
        (ipaddress.IPv4Address, ipaddress.IPv6Address) or None.
        Sync function (CPU bound, fast enough to run in loop).
        """
        clean_qname = qname_str.lower().rstrip(".")
        zone_suffix = f".{NAT64_SUFFIX}"

        if clean_qname == NAT64_SUFFIX or not clean_qname.endswith(zone_suffix):
            return None

        content = clean_qname[: -len(zone_suffix)]
        parts = content.split(".")

        if len(parts) < 2 or len(parts) > 3:
            return None

        ipv4_part_str = parts[0]
        customer_id_str = parts[-1]
        site_id_str = "0"

        if len(parts) == 3:
            site_id_str = parts[1]

        if customer_id_str.startswith("t"):
            customer_id_str = customer_id_str[1:]

        try:
            customer_id = int(customer_id_str, 16)
            if customer_id > 0xFFFFFF:
                return None
        except ValueError:
            return None

        try:
            site_id = int(site_id_str, 16)
            if site_id > 0xFF:
                return None
        except ValueError:
            return None

        try:
            dotted_ipv4 = ipv4_part_str.replace("-", ".")
            ipv4_obj = ipaddress.IPv4Address(dotted_ipv4)
            ipv4_int = int(ipv4_obj)
        except (ValueError, ipaddress.AddressValueError):
            return None

        base_net = ipaddress.IPv6Network(BASE_PREFIX + "/96")
        base_int = int(base_net.network_address)

        constructed_suffix = (customer_id << 40) | (site_id << 32) | ipv4_int
        final_int = base_int | constructed_suffix

        return ipv4_obj, ipaddress.IPv6Address(final_int)

    def resolve(self, qname_str):
        parsed = self.parse(qname_str)
        if not parsed:
            return None
        return parsed[1]

    def resolve_ipv4(self, qname_str):
        parsed = self.parse(qname_str)
        if not parsed:
            return None
        return parsed[0]


async def resolve_upstream_dns64(qname, nat64_net):
    """
    Queries upstream for A records and synthesizes AAAA records async.
    """
    try:
        upstream_q = DNSRecord.question(qname, "A")
        response_data = await query_upstream_async(
            upstream_q.pack(), UPSTREAM_DNS, UPSTREAM_PORT
        )

        if not response_data:
            return []

        upstream_reply = DNSRecord.parse(response_data)
        if upstream_reply.header.rcode != RCODE.NOERROR:
            return []

        synthesized_ips = []
        prefix_int = int(nat64_net.network_address)

        for rr in upstream_reply.rr:
            if rr.rtype == QTYPE.A:
                ipv4_addr = ipaddress.IPv4Address(str(rr.rdata))
                ipv4_int = int(ipv4_addr)
                synth_int = prefix_int | ipv4_int
                synthesized_ips.append(ipaddress.IPv6Address(synth_int))

        return synthesized_ips

    except Exception as e:
        print(f"Upstream resolution failed for {qname}: {e}")
        return []


def qtype_name(qtype):
    try:
        return QTYPE[qtype]
    except Exception:
        return str(qtype)


class DNSServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Fire and forget task for each request to ensure concurrency
        asyncio.create_task(self.handle_request(data, addr))

    async def handle_request(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = request.q.qtype
            qtype_label = qtype_name(qtype)

            reply = DNSRecord(
                DNSHeader(
                    id=request.header.id,
                    qr=1,
                    aa=1,
                    ra=1,
                    rd=request.header.rd,
                ),
                q=request.q,
            )

            resolver = NAT64Resolver()
            custom_record = resolver.parse(qname)

            if custom_record:
                result_ipv4, result_ipv6 = custom_record

                if qtype == QTYPE.A:
                    reply.add_answer(
                        RR(
                            rname=qname,
                            rtype=QTYPE.A,
                            rclass=1,
                            ttl=300,
                            rdata=A(str(result_ipv4)),
                        )
                    )
                    print(f"Query: {qname} [Custom A] -> {result_ipv4}")
                elif qtype == QTYPE.AAAA:
                    reply.add_answer(
                        RR(
                            rname=qname,
                            rtype=QTYPE.AAAA,
                            rclass=1,
                            ttl=300,
                            rdata=AAAA(str(result_ipv6)),
                        )
                    )
                    print(f"Query: {qname} [Custom AAAA] -> {result_ipv6}")
                elif qtype == QTYPE.ANY:
                    reply.add_answer(
                        RR(
                            rname=qname,
                            rtype=QTYPE.A,
                            rclass=1,
                            ttl=300,
                            rdata=A(str(result_ipv4)),
                        )
                    )
                    reply.add_answer(
                        RR(
                            rname=qname,
                            rtype=QTYPE.AAAA,
                            rclass=1,
                            ttl=300,
                            rdata=AAAA(str(result_ipv6)),
                        )
                    )
                    print(
                        f"Query: {qname} [Custom ANY] -> A {result_ipv4}, AAAA {result_ipv6}"
                    )
                else:
                    print(f"Query: {qname} [Custom {qtype_label}] -> No data")

                self.transport.sendto(reply.pack(), addr)
                return

            if qtype == QTYPE.AAAA:
                upstream_aaaa_data = await query_upstream_async(
                    data, UPSTREAM_DNS, UPSTREAM_PORT
                )

                if upstream_aaaa_data:
                    try:
                        upstream_aaaa_reply = DNSRecord.parse(upstream_aaaa_data)
                        if upstream_aaaa_reply.header.rcode != RCODE.NOERROR:
                            self.transport.sendto(upstream_aaaa_data, addr)
                            print(
                                f"Query: {qname} [Upstream AAAA] -> RCODE {upstream_aaaa_reply.header.rcode}"
                            )
                            return

                        if upstream_aaaa_reply.rr:
                            self.transport.sendto(upstream_aaaa_data, addr)
                            print(
                                f"Query: {qname} [Upstream AAAA] -> {len(upstream_aaaa_reply.rr)} records"
                            )
                            return
                    except Exception as e:
                        print(
                            f"Failed to parse upstream AAAA response for {qname}: {e}"
                        )
                        self.transport.sendto(upstream_aaaa_data, addr)
                        return

                nat64_net = await load_nat64_prefix_async()
                if nat64_net:
                    synthesized_ips = await resolve_upstream_dns64(qname, nat64_net)
                    if synthesized_ips:
                        for ip in synthesized_ips:
                            reply.add_answer(
                                RR(
                                    rname=qname,
                                    rtype=QTYPE.AAAA,
                                    rclass=1,
                                    ttl=60,
                                    rdata=AAAA(str(ip)),
                                )
                            )
                        print(
                            f"Query: {qname} [DNS64] -> {len(synthesized_ips)} records"
                        )
                        self.transport.sendto(reply.pack(), addr)
                        return

                if upstream_aaaa_data:
                    self.transport.sendto(upstream_aaaa_data, addr)
                    print(f"Query: {qname} [Upstream AAAA] -> Empty response")
                else:
                    reply.header.rcode = RCODE.SERVFAIL
                    self.transport.sendto(reply.pack(), addr)
                    print(f"Query: {qname} [Failed] -> Upstream timeout")
                return

            upstream_response = await query_upstream_async(
                data, UPSTREAM_DNS, UPSTREAM_PORT
            )
            if upstream_response:
                self.transport.sendto(upstream_response, addr)
                print(f"Query: {qname} [Upstream {qtype_label}] -> Forwarded")
            else:
                reply.header.rcode = RCODE.SERVFAIL
                self.transport.sendto(reply.pack(), addr)
                print(f"Query: {qname} [Failed {qtype_label}] -> Upstream timeout")

        except Exception as e:
            print(f"Error processing request from {addr}: {e}")


async def main():
    loop = asyncio.get_running_loop()

    initial_check = await load_nat64_prefix_async()
    if not initial_check:
        print(
            f"WARNING: {NAT64_PREFIX_FILE} not found or invalid. Fallback DNS64 will not work."
        )

    # Get IPs specifically for tailscale0
    listen_ips = get_interface_ipv6_addrs(INTERFACE_NAME)

    if not listen_ips:
        print(f"No IPv6 addresses found on {INTERFACE_NAME}. Exiting.")
        return

    transports = []

    try:
        # Create a server endpoint for every IP found on the interface
        for ip in listen_ips:
            print(f"Binding to {INTERFACE_NAME} -> [{ip}]:{LISTEN_PORT}")
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: DNSServerProtocol(), local_addr=(ip, LISTEN_PORT)
                )
                transports.append(transport)
            except OSError as e:
                print(f"Failed to bind {ip}: {e}")

        if not transports:
            print("Could not bind to any addresses.")
            return

        print("DNS Server is running.")

        try:
            await asyncio.Future()  # Run forever
        finally:
            for t in transports:
                t.close()

    except PermissionError:
        print(
            f"Permission denied. Try running with sudo/admin privileges to bind to port {LISTEN_PORT}."
        )
    except Exception as e:
        print(f"Fatal error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
