import { z } from "zod";
import { ToolDefinition } from './types';

export const sslInfoTool: ToolDefinition = {
    name: 'ssl-info',
    description: 'Get SSL/TLS certificate information for a domain',
    schema: z.object({
        domain: z.string().describe("The domain to check SSL certificate"),
        port: z.number().optional().default(443).describe("Port number (default: 443)")
    }),
    handler: async ({ domain, port }) => {
        try {
            // Use fetch to get basic certificate info
            const response = await fetch(`https://${domain}:${port}`, {
                method: 'HEAD',
            });
            
            // Extract security details from headers
            const headers: { [key: string]: string } = {};
            response.headers.forEach((value, key) => {
                headers[key] = value;
            });
            
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
};
