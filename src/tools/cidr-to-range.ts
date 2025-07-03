import { z } from "zod";
import { ToolDefinition } from './types';

export const cidrToRangeTool: ToolDefinition = {
    name: 'cidr-to-range',
    description: 'Convert CIDR notation to IP range',
    schema: {
        cidr: z.string().describe("CIDR notation (e.g., 192.168.1.0/24)")
    },
    handler: async ({ cidr }) => {
        try {
            // Split the CIDR notation
            const [ipPart, prefixPart] = cidr.split('/');
            const prefix = parseInt(prefixPart);
            
            if (isNaN(prefix) || prefix < 0 || prefix > 32) {
                throw new Error("Invalid CIDR prefix. Must be between 0 and 32.");
            }
            
            // Convert IP to binary
            const ipOctets = ipPart.split('.').map(Number);
            if (ipOctets.length !== 4 || ipOctets.some((octet: number) => isNaN(octet) || octet < 0 || octet > 255)) {
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
            
            // Calculate usable host addresses (excluding network and broadcast)
            const usableAddresses = Math.max(0, numAddresses - 2);
            
            const result = {
                cidr: cidr,
                networkAddress: firstIP,
                broadcastAddress: lastIP,
                firstUsableIP: numAddresses > 2 ? [
                    (networkNum + 1 >> 24) & 0xFF,
                    (networkNum + 1 >> 16) & 0xFF,
                    (networkNum + 1 >> 8) & 0xFF,
                    (networkNum + 1) & 0xFF
                ].join('.') : 'N/A',
                lastUsableIP: numAddresses > 2 ? [
                    (broadcastNum - 1 >> 24) & 0xFF,
                    (broadcastNum - 1 >> 16) & 0xFF,
                    (broadcastNum - 1 >> 8) & 0xFF,
                    (broadcastNum - 1) & 0xFF
                ].join('.') : 'N/A',
                totalAddresses: numAddresses,
                usableAddresses: usableAddresses,
                subnetMask: [
                    (subnetMask >> 24) & 0xFF,
                    (subnetMask >> 16) & 0xFF,
                    (subnetMask >> 8) & 0xFF,
                    subnetMask & 0xFF
                ].join('.')
            };
            
            return { 
                content: [{
                    type: "text",
                    text: `CIDR to Range conversion for ${cidr}:\n\n${JSON.stringify(result, null, 2)}`
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
};
