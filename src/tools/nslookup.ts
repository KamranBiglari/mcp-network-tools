import { z } from "zod";
import { ToolDefinition } from './types';

// DNS over HTTPS function
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

export const nslookupTool: ToolDefinition = {
    name: 'nslookup',
    description: 'Get NSLOOKUP information',
    schema: {
        domain: z.string().describe("The domain to query"),
        type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']).optional().default('A')
            .describe("The type of DNS record to query (default: A)"),
    },
    handler: async ({ domain, type }) => {
        try {
            const result = await dnsOverHttps(domain, type);
            return {
                content: [{
                    type: "text",
                    text: `DNS lookup for ${domain} (${type} records):\n\n${JSON.stringify(result, null, 2)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return {
                content: [{
                    type: "text",
                    text: `Error performing DNS lookup for ${domain}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
