import { z } from "zod";
import { ToolDefinition } from './types';

export const geolocateIpTool: ToolDefinition = {
    name: 'geolocate-ip',
    description: 'Get geographical location information for an IP address',
    schema: z.object({
        ip: z.string().ip().describe("The IP address to geolocate")
    }),
    handler: async ({ ip }) => {
        try {
            // Use a free geolocation API like ipapi.co or ip-api.com
            const response = await fetch(`http://ip-api.com/json/${ip}`);
            
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }
            
            const data = await response.json();
            
            return {
                content: [{
                    type: "text",
                    text: `Geolocation information for IP ${ip}:\n\n${JSON.stringify(data, null, 2)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return {
                content: [{
                    type: "text",
                    text: `Error geolocating IP ${ip}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
