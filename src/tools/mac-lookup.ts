import { z } from "zod";
import { ToolDefinition } from './types';

export const macLookupTool: ToolDefinition = {
    name: 'mac-lookup',
    description: 'Look up MAC address vendor information',
    schema: {
        mac: z.string().describe("MAC address to lookup")
    },
    handler: async ({ mac }) => {
        try {
            // Validate MAC address format
            if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
                throw new Error("Invalid MAC address format. Use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.");
            }
            
            const macPrefix = mac.toUpperCase().replace(/[:-]/g, '').slice(0, 6);
            
            try {
                // First try using the macvendors API
                const response = await fetch(`https://api.macvendors.com/${macPrefix}`, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; MCP-Network-Tools/1.0)'
                    }
                });
                
                if (response.ok) {
                    const vendorInfo = await response.text();
                    
                    const result = {
                        macAddress: mac,
                        oui: macPrefix,
                        vendor: vendorInfo,
                        apiSource: "macvendors.com"
                    };
                    
                    return { 
                        content:[{
                            type: "text",
                            text: `Vendor information for MAC ${mac}:\n\n${JSON.stringify(result, null, 2)}`
                        }]
                    };
                } else if (response.status === 404) {
                    return { 
                        content:[{
                            type: "text",
                            text: `MAC address ${mac} with OUI ${macPrefix}: Vendor not found in database.`
                        }]
                    };
                }
            } catch (apiError) {
                // API call failed, provide fallback information
                console.error("MAC vendor API failed:", apiError);
            }
            
            // Fallback: Provide generic information
            const result = {
                macAddress: mac,
                oui: macPrefix,
                vendor: "Unknown - API unavailable",
                note: "MAC vendor API is not accessible. The OUI (Organizationally Unique Identifier) is the first 6 characters of the MAC address and identifies the manufacturer."
            };
            
            return { 
                content:[{
                    type: "text",
                    text: `MAC address lookup for ${mac}:\n\n${JSON.stringify(result, null, 2)}`
                }]
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
};
