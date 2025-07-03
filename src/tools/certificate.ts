import { z } from "zod";
import { ToolDefinition } from './types';
import { generateSelfSignedCertificate } from '../utils/certificate';

export const certificateTool: ToolDefinition = {
    name: 'generate-certificate',
    description: 'Generate a self-signed SSL/TLS certificate',
    schema: z.object({
        commonName: z.string().describe("Common Name (CN) for the certificate"),
        organization: z.string().optional().default("My Organization").describe("Organization name"),
        validityDays: z.number().optional().default(365).describe("Validity period in days"),
        country: z.string().optional().default("US").describe("Country code (e.g., US, GB, CA)")
    }),
    handler: async ({ commonName, organization, validityDays, country }) => {
        try {
            const certData = generateSelfSignedCertificate(
                commonName,
                organization,
                validityDays,
                country
            );

            return {
                content: [{
                    type: "text",
                    text: `Self-signed certificate generated successfully for ${commonName}

**Certificate Details:**
- Common Name: ${commonName}
- Organization: ${organization}
- Validity: ${validityDays} days
- Country: ${country}

**Certificate (PEM format):**
\`\`\`
${certData.certificate}
\`\`\`

**Private Key (PEM format):**
\`\`\`
${certData.privateKey}
\`\`\`

**Public Key (PEM format):**
\`\`\`
${certData.publicKey}
\`\`\`

**Usage Instructions:**
1. Save the certificate to a .crt or .pem file
2. Save the private key to a .key file  
3. Keep the private key secure and never share it
4. For web servers, configure both files in your SSL/TLS settings

**Note:** This is a self-signed certificate. For production use, obtain certificates from a trusted Certificate Authority (CA).`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text",
                    text: `Error generating certificate: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }
};
