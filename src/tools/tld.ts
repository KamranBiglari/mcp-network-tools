import { z } from "zod";
import { whoisTld } from 'whoiser';
import { ToolDefinition } from './types';

export const tldTool: ToolDefinition = {
    name: 'tld',
    description: 'Get TLD whois information',
    schema: z.object({
        tld: z.string().describe("The top-level domain to query"),
    }),
    handler: async ({ tld }) => {
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
};
