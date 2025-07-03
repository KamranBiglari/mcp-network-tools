import { z } from "zod";
import { whoisAsn } from 'whoiser';
import { ToolDefinition } from './types';

export const asnTool: ToolDefinition = {
    name: 'asn',
    description: 'Get ASN whois information',
    schema: {
        asn: z.string()
            .regex(/^(AS)?\d+$/i, "ASN must be in the format AS12345 or 12345")
            .transform((val) => parseInt(val.slice(2), 10)) // Remove 'AS' prefix if present and convert to number
            .describe("The ASN to query, e.g. AS12345 or 12345"),
    },
    handler: async ({ asn }) => {
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
};
