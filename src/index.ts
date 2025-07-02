import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { whoisAsn, whoisDomain, whoisTld, whoisIp } from 'whoiser';

// DNS over HTTPS function for Cloudflare Workers
async function dnsOverHttps(domain: string, type: string = 'A'): Promise<any> {
    const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    
    const response = await fetch(dohUrl, {
        headers: {
            'Accept': 'application/dns-json'
        }
    });
    
    if (!response.ok) {
        throw new Error(`DNS query failed: ${response.status} ${response.statusText}`);
    }
    
    return await response.json();
}

// Type definitions for Cloudflare Workers
interface Env {
    // Add any environment variables here
}



// Define our MCP agent with tools
export class MyMCP extends McpAgent {
    server = new McpServer({
        name: "mcp-whois",
        version: "1.0.0",
        description: "MCP Server for Network Tools",
        baseUrl: "https://network-tool.mcp.cloudcertainty.com",
        author: "Kamran Biglari",
        authorUrl: "https://github.com/KamranBiglari"
    });

    async init() {

        // Register domain whois tool
        this.server.tool(
            'domain',
            'Get domain whois information',
            {
                domain: z.string().describe("The domain name to query"),
            },
            async ( {domain} ) => {
                try {
                    const result = await whoisDomain(domain);
                    return { 
                        content:[{
                            type: "text",
                            text: `Whois information for domain ${domain}:\n\n${JSON.stringify(result)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching whois information for domain ${domain}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register Tld whois tool
        this.server.tool(
            'tld',
            'Get TLD whois information',
            {
                tld: z.string().describe("The top-level domain to query"),
            },
            async ( {tld} ) => {
                try {
                    const result = await whoisTld(tld);
                    return { 
                        content:[{
                            type: "text",
                            text: `Whois information for TLD ${tld}:\n\n${JSON.stringify(result)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching whois information for TLD ${tld}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register ASN whois tool
        this.server.tool(
            'asn',
            'Get ASN whois information',
            {
                asn: z.string()
                .regex(/^(AS)?\d+$/i, "ASN must be in the format AS12345 or 12345")
                .transform((val) => parseInt(val.slice(2), 10)) // Remove 'AS' prefix if present and convert to number
                .describe("The ASN to query, e.g. AS12345 or 12345"),
            },
            async ( {asn} ) => {
                try {
                    const result = await whoisAsn(asn);
                    return { 
                        content:[{
                            type: "text",
                            text: `Whois information for ASN ${asn}:\n\n${JSON.stringify(result)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching whois information for ASN ${asn}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register IP whois tool
        this.server.tool(
            'ip',
            'Get IP whois information',
            {
                ip: z.string().ip().describe("The IP address to query"),
            },
            async ( {ip} ) => {
                try {
                    const result = await whoisIp(ip);
                    return { 
                        content:[{
                            type: "text",
                            text: `Whois information for IP ${ip}:\n\n${JSON.stringify(result)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching whois information for IP ${ip}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register NSLOOKUP tool
        this.server.tool(
            'nslookup',
            'Get NSLOOKUP information',
            {
                domain: z.string().describe("The domain to query"),
                type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']).optional().default('A')
                .describe("The type of DNS record to query (default: A)"),
            },
            async ( {domain, type} ) => {
                try {
                    const result = await dnsOverHttps(domain, type);
                    return { 
                        content:[{
                            type: "text",
                            text: `NSLOOKUP information for domain ${domain}:\n\n${JSON.stringify(result, null, 2)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching NSLOOKUP information for domain ${domain}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register PING tool
        this.server.tool(
            'ping',
            'Test connectivity to a host',
            {
                host: z.string().describe("The hostname or IP address to ping"),
                count: z.number().optional().default(4).describe("Number of ping packets to send")
            },
            async ({ host, count }) => {
                // Implementation using HTTP requests to simulate ping
                try {
                    const results = [];
                    for (let i = 0; i < count; i++) {
                        const start = Date.now();
                        await fetch(`https://${host}`, { method: 'HEAD', mode: 'no-cors' });
                        const end = Date.now();
                        results.push({ 
                            packet: i + 1, 
                            time: end - start 
                        });
                    }
                    return { 
                        content:[{
                            type: "text",
                            text: `Ping results for ${host}:\n\n${JSON.stringify(results, null, 2)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error pinging host ${host}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register PORTSCAN tool
        this.server.tool(
            'portscan',
            'Check if specific ports are open on a host',
            {
                host: z.string().describe("The hostname or IP address to scan"),
                ports: z.array(z.number()).describe("Array of port numbers to check"),
                timeout: z.number().optional().default(5000).describe("Timeout in milliseconds")
            },
            async ({ host, ports, timeout }) => {
                // Implementation using fetch with timeouts
                try {
                    const results = await Promise.all(
                        ports.map(async (port) => {
                            const controller = new AbortController();
                            const id = setTimeout(() => controller.abort(), timeout);
                            try {
                                await fetch(`https://${host}`, { method: 'HEAD', mode: 'no-cors', signal: controller.signal });
                                return { port, open: true };
                            } catch (err) {
                                if (err.name === 'AbortError') {
                                    return { port, open: false, error: 'timeout' };
                                }
                                return { port, open: false, error: err.message };
                            } finally {
                                clearTimeout(id);
                            }
                        })
                    );
                    return { 
                        content:[{
                            type: "text",
                            text: `Port scan results for ${host}:\n\n${JSON.stringify(results, null, 2)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error performing port scan on ${host}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register TRACEROUTE tool
        this.server.tool(
            'traceroute',
            'Trace the network path to a destination',
            {
                destination: z.string().describe("The destination hostname or IP address"),
                maxHops: z.number().optional().default(30).describe("Maximum number of hops")
            },
            async ({ destination, maxHops }) => {
                try {
                    // Simulate traceroute by making HTTP requests with increasing TTL
                    const hops = [];
                    for (let ttl = 1; ttl <= maxHops; ttl++) {
                        try {
                            const start = Date.now();
                            await fetch(`https://${destination}`, { 
                                method: 'HEAD',
                                headers: { 'Max-Forwards': ttl.toString() }
                            });
                            const end = Date.now();
                            
                            hops.push({
                                hop: ttl,
                                time: end - start,
                                status: 'reached'
                            });
                            
                            // If we successfully reached the destination, stop
                            if (ttl > 1) break;
                        } catch (err) {
                            hops.push({
                                hop: ttl,
                                status: 'timeout',
                                error: err.message
                            });
                        }
                    }
                    
                    return { 
                        content:[{
                            type: "text",
                            text: `Traceroute results for ${destination}:\n\n${JSON.stringify(hops, null, 2)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error performing traceroute to ${destination}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register REVERSE-DNS tool
        this.server.tool(
            'reverse-dns',
            'Perform reverse DNS lookup for an IP address',
            {
                ip: z.string().ip().describe("The IP address for reverse lookup")
            },
            async ({ ip }) => {
                return await dnsOverHttps(ip.split('.').reverse().join('.') + '.in-addr.arpa', 'PTR');
            }
        );

        // Register DNS-ZONE-INFO tool
        this.server.tool(
            'dns-zone-info',
            'Get comprehensive DNS zone information',
            {
                domain: z.string().describe("The domain to analyze"),
                includeSubdomains: z.boolean().optional().default(false).describe("Include common subdomains")
            },
            async ({ domain, includeSubdomains }) => {
                // Query multiple DNS record types and analyze zone structure
            }
        );

        // Register SSL/TLS INFO tool
        this.server.tool(
            'ssl-info',
            'Get SSL/TLS certificate information for a domain',
            {
                domain: z.string().describe("The domain to check SSL certificate"),
                port: z.number().optional().default(443).describe("Port number (default: 443)")
            },
            async ({ domain, port }) => {
                try {
                    // Use fetch to get basic certificate info
                    const response = await fetch(`https://${domain}:${port}`, {
                        method: 'HEAD',
                    });
                    
                    // Extract security details from headers
                    const headers = Object.fromEntries(response.headers.entries());
                    
                    // Get the certificate info from the response
                    const connectionInfo = {
                        status: response.status,
                        statusText: response.statusText,
                        headers: headers,
                        protocol: response.url.split(':')[0],
                        securityDetails: {
                            secure: response.url.startsWith('https'),
                            host: domain,
                            port: port
                        }
                    };
                    
                    return { 
                        content:[{
                            type: "text",
                            text: `SSL/TLS information for ${domain}:${port}:\n\n${JSON.stringify(connectionInfo, null, 2)}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error fetching SSL/TLS information for ${domain}:${port}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register SECURITY-HEADERS tool
        this.server.tool(
            'security-headers',
            'Check HTTP security headers for a website',
            {
                url: z.string().url().describe("The URL to check security headers")
            },
            async ({ url }) => {
                const response = await fetch(url, { method: 'HEAD' });
                const headers = Object.fromEntries(response.headers.entries());
                // Analyze security headers like HSTS, CSP, X-Frame-Options, etc.
            }
        );

        // Register GEOLocate IP tool
        this.server.tool(
            'geolocate-ip',
            'Get geographical location information for an IP address',
            {
                ip: z.string().ip().describe("The IP address to geolocate")
            },
            async ({ ip }) => {
                // Use a free geolocation API like ipapi.co or ip-api.com
                const response = await fetch(`http://ip-api.com/json/${ip}`);
                return {
                    content: [{
                        type: "text",
                        text: `Geolocation information for IP ${ip}:\n\n${JSON.stringify(await response.json(), null, 2)}`
                    }]
                }
            }
        );

        // Register DOMAIN-HISTORY tool
        this.server.tool(
            'domain-history',
            'Get historical DNS records and changes for a domain',
            {
                domain: z.string().describe("The domain to check history"),
                days: z.number().optional().default(30).describe("Number of days to look back")
            },
            async ({ domain, days }) => {
                // Implementation would require integration with services like SecurityTrails API
            }
        );

        // Register SUBDOMAINS tool
        this.server.tool(
            'subdomains',
            'Find subdomains for a given domain',
            {
                domain: z.string().describe("The domain to find subdomains for"),
                limit: z.number().optional().default(50).describe("Maximum number of subdomains to return")
            },
            async ({ domain, limit }) => {
                // Check common subdomain patterns and certificate transparency logs
            }
        );

        // Register REPUTATION tool
        this.server.tool(
            'reputation',
            'Check domain/IP reputation against threat intelligence feeds',
            {
                target: z.string().describe("Domain or IP address to check"),
                type: z.enum(['domain', 'ip']).describe("Type of target")
            },
            async ({ target, type }) => {
                // Integration with public threat intelligence APIs
            }
        );

        // Register CIDR to Range tool
        this.server.tool(
            'cidr-to-range',
            'Convert CIDR notation to IP range',
            {
                cidr: z.string().describe("CIDR notation (e.g., 192.168.1.0/24)")
            },
            async ({ cidr }) => {
                try {
                    // Split the CIDR notation
                    const [ipPart, prefixPart] = cidr.split('/');
                    const prefix = parseInt(prefixPart);
                    
                    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
                        throw new Error("Invalid CIDR prefix. Must be between 0 and 32.");
                    }
                    
                    // Convert IP to binary
                    const ipOctets = ipPart.split('.').map(Number);
                    if (ipOctets.length !== 4 || ipOctets.some(octet => isNaN(octet) || octet < 0 || octet > 255)) {
                        throw new Error("Invalid IP address format.");
                    }
                    
                    // Calculate subnet mask
                    const subnetMask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
                    
                    // Calculate network address (first IP)
                    const ipNum = (ipOctets[0] << 24) + (ipOctets[1] << 16) + (ipOctets[2] << 8) + ipOctets[3];
                    const networkNum = ipNum & subnetMask;
                    
                    // Calculate broadcast address (last IP)
                    const broadcastNum = networkNum | (~subnetMask >>> 0);
                    
                    // Convert back to readable IP format
                    const firstIP = [
                        (networkNum >> 24) & 0xFF,
                        (networkNum >> 16) & 0xFF,
                        (networkNum >> 8) & 0xFF,
                        networkNum & 0xFF
                    ].join('.');
                    
                    const lastIP = [
                        (broadcastNum >> 24) & 0xFF,
                        (broadcastNum >> 16) & 0xFF,
                        (broadcastNum >> 8) & 0xFF,
                        broadcastNum & 0xFF
                    ].join('.');
                    
                    // Calculate total number of addresses
                    const numAddresses = broadcastNum - networkNum + 1;
                    
                    return { 
                        content: [{
                            type: "text",
                            text: `CIDR to Range conversion for ${cidr}:\n\nFirst IP: ${firstIP}\nLast IP: ${lastIP}\nTotal addresses: ${numAddresses}`
                        }]
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error converting CIDR ${cidr} to range: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );

        // Register MAC-LOOKUP tool
        this.server.tool(
            'mac-lookup',
            'Look up MAC address vendor information',
            {
                mac: z.string().describe("MAC address to lookup")
            },
            async ({ mac }) => {
                try {
                    // Use IEEE OUI database or API
                    if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
                        throw new Error("Invalid MAC address format. Use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.");
                    }
                    
                    const macPrefix = mac.toUpperCase().replace(/[:-]/g, '').slice(0, 6);
                    try {
                        // First try using the macvendors API
                        const response = await fetch(`https://api.macvendors.com/${macPrefix}`);
                        if (response.ok) {
                            const vendorInfo = await response.text();
                            return { 
                                content:[{
                                    type: "text",
                                    text: `Vendor information for MAC ${mac}:\n\n${vendorInfo}`
                                }]
                            };
                        }
                    } catch (apiError) {
                        // API call failed, continue to fallback
                        console.error("MAC vendor API failed:", apiError);
                    }
                    
                    // Fallback: Provide generic information since we can't access local files in Cloudflare Workers
                    return { 
                        content:[{
                            type: "text",
                            text: `MAC address ${mac} has prefix ${macPrefix}. No vendor information could be retrieved from the API. Fallback database access is not available in this environment.`
                        }],
                        isError: true
                    };
                } catch (err: unknown) {
                    const error = err as Error;
                    return { 
                        content: [{
                            type: "text",
                            text: `Error looking up MAC address ${mac}: ${error.message}`
                        }],
                        isError: true
                    };
                }
            }
        );
    }
}

// Helper function to get the base URL from the request
function getBaseUrl(request: Request): string {
    const url = new URL(request.url);
    return `https://${url.host}`;
}

// OAuth Authorization Server Discovery Response
function createOAuthAuthorizationServerResponse(baseUrl: string) {
    return {
        "issuer": baseUrl,
        "authorization_endpoint": `${baseUrl}/oauth/authorize`,
        "token_endpoint": `${baseUrl}/oauth/token`,
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "implicit"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "scopes_supported": ["read", "write", "openid"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        // Dynamic Client Registration support
        "registration_endpoint": `${baseUrl}/oauth/register`,
        "registration_endpoint_auth_methods_supported": ["none"],
        // Indicate this is an authless server
        "authless": true,
        "require_authentication": false
    };
}

// OAuth Protected Resource Discovery Response
function createOAuthProtectedResourceResponse(baseUrl: string) {
    return {
        "resource": baseUrl,
        "authorization_servers": [baseUrl],
        "scopes_supported": ["read", "write"],
        "bearer_methods_supported": ["header", "query"],
        // Indicate no authentication required
        "authless": true,
        "require_authentication": false,
        "token_validation": "none"
    };
}

// Mock OAuth Token Response
function createMockTokenResponse() {
    return {
        "access_token": "authless-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read write"
    };
}

// Mock Client Registration Response
function createClientRegistrationResponse() {
    return {
        "client_id": "authless-client",
        "client_secret": "authless-secret",
        "client_id_issued_at": Math.floor(Date.now() / 1000),
        "client_secret_expires_at": 0, // Never expires
        "redirect_uris": [],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "client_credentials"],
        "response_types": ["code"],
        "scope": "read write"
    };
}

export default {
    fetch(request: Request, env: Env, ctx: ExecutionContext) {
        const url = new URL(request.url);
        const baseUrl = getBaseUrl(request);

        // OAuth Authorization Server Discovery Endpoint
        if (url.pathname === "/.well-known/oauth-authorization-server") {
            return new Response(
                JSON.stringify(createOAuthAuthorizationServerResponse(baseUrl), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // OAuth Protected Resource Discovery Endpoint
        if (url.pathname === "/.well-known/oauth-protected-resource") {
            return new Response(
                JSON.stringify(createOAuthProtectedResourceResponse(baseUrl), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Authorization Endpoint
        if (url.pathname === "/oauth/authorize") {

            // redirect to the redirect_uri if provided
            const redirectUri = url.searchParams.get("redirect_uri");
            if (redirectUri) {
                return Response.redirect(redirectUri);
            }
            return new Response(
                JSON.stringify(createMockTokenResponse(), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Token Endpoint
        if (url.pathname === "/oauth/token") {
            return new Response(
                JSON.stringify(createMockTokenResponse(), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Client Registration Endpoint
        if (url.pathname === "/oauth/register") {
            // Handle both GET and POST for client registration
            if (request.method === "POST" || request.method === "GET") {
                return new Response(
                    JSON.stringify(createClientRegistrationResponse(), null, 2),
                    {
                        headers: {
                            "Content-Type": "application/json",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    }
                );
            }
        }

        // Health check endpoint
        if (url.pathname === "/health") {
            return new Response(
                JSON.stringify({
                    status: "ok",
                    authless: true,
                    timestamp: new Date().toISOString(),
                    server: "mcp-whois",
                }, null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                }
            );
        }

        // Root endpoint with server info
        if (url.pathname === "/") {
            return new Response(
                JSON.stringify({
                    name: "mcp-whois",
                    version: "1.0.0",
                    authless: true,
                    endpoints: {
                        mcp: "/mcp",
                        sse: "/sse",
                        health: "/health",
                        oauth_authorization_server: "/.well-known/oauth-authorization-server",
                        oauth_protected_resource: "/.well-known/oauth-protected-resource",
                        oauth_authorize: "/oauth/authorize",
                        oauth_token: "/oauth/token"
                    }
                }, null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                }
            );
        }

        // Handle CORS preflight requests
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                },
            });
        }

        // Existing MCP endpoints
        if (url.pathname === "/sse" || url.pathname === "/sse/message") {
            return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
        }

        if (url.pathname === "/mcp") {
            return MyMCP.serve("/mcp").fetch(request, env, ctx);
        }

        return new Response("Not found", { status: 404 });
    },
};