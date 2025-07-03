import { z } from "zod";
import { ToolDefinition } from './types';
import { generateSelfSignedCertificate } from '../utils/certificate';

export const certificateTool: ToolDefinition = {
    name: 'generate-certificate',
    description: 'Generate a self-signed SSL/TLS certificate',
    schema: {
        commonName: z.string().describe("Common Name (CN) for the certificate"),
        organization: z.string().optional().default("My Organization").describe("Organization name"),
        validityDays: z.number().optional().default(365).describe("Validity period in days"),
        country: z.string().optional().default("US").describe("Country code (e.g., US, GB, CA)")
    },
    handler: async ({ commonName, organization, validityDays, country }) => {
        try {
            const certData = generateSelfSignedCertificate(
                commonName,
                organization,
                validityDays,
                country
            );

            return {
                content: [
                    // Certificate details as text
                    {
                        type: "text",
                        text: `# Self-signed Certificate Generated Successfully

## Certificate Details:
- **Common Name**: ${commonName}
- **Organization**: ${organization}
- **Validity Period**: ${validityDays} days
- **Country**: ${country}
- **Generated**: ${new Date().toISOString()}

## Files Generated:
1. **${commonName.replace(/[^a-z0-9]/gi, '_')}.crt** - Certificate file
2. **${commonName.replace(/[^a-z0-9]/gi, '_')}.key** - Private key file  
3. **${commonName.replace(/[^a-z0-9]/gi, '_')}.pub** - Public key file

## Usage Instructions:
1. Save each file with the suggested filename
2. Keep the private key (*.key) secure and never share it
3. For web servers, configure both the certificate and private key files in your SSL/TLS settings
4. The public key file is provided for reference and verification

## Security Note:
⚠️ This is a self-signed certificate. For production use, obtain certificates from a trusted Certificate Authority (CA).`
                    },
                    // Certificate file as resource (as blob for download)
                    {
                        type: "resource",
                        resource: {
                            uri: `file://${commonName.replace(/[^a-z0-9]/gi, '_')}.crt`,
                            mimeType: "application/x-x509-ca-cert",
                            blob: btoa(certData.certificate)
                        }
                    },
                    // Private key file as resource (as blob for download)
                    {
                        type: "resource", 
                        resource: {
                            uri: `file://${commonName.replace(/[^a-z0-9]/gi, '_')}.key`,
                            mimeType: "application/x-pem-file",
                            blob: btoa(certData.privateKey)
                        }
                    },
                    // Public key file as resource (as blob for download)
                    {
                        type: "resource",
                        resource: {
                            uri: `file://${commonName.replace(/[^a-z0-9]/gi, '_')}.pub`,
                            mimeType: "application/x-pem-file",
                            blob: btoa(certData.publicKey)
                        }
                    }
                ]
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
