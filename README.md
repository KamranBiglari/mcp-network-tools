# MCP Network Tools 🌐

A comprehensive Model Context Protocol (MCP) server providing powerful network analysis and SSL certificate generation tools for AI assistants.

![MCP Network Tools in Action](./screenshots/Screenshot%202025-07-03%20231927.png)

## 🚀 Live Demo

**Try it live**: https://network-tools.mcp.cloudcertainty.com/mcp

## ✨ Features

### 🔍 Network Analysis Tools
- **Domain WHOIS** - Get detailed domain registration information
- **IP WHOIS** - Retrieve IP address ownership and network details  
- **ASN Lookup** - Query Autonomous System Number information
- **TLD WHOIS** - Top-level domain registry information
- **DNS Lookup** - Comprehensive DNS record queries (A, AAAA, MX, TXT, etc.)
- **IP Geolocation** - Geographic location and ISP information
- **Port Scanning** - Check open ports on target hosts
- **Ping** - Network connectivity testing
- **CIDR to IP Range** - Convert CIDR notation to IP ranges
- **MAC Address Lookup** - Identify device manufacturers

### 🔐 SSL/TLS Tools
- **SSL Certificate Info** - Analyze existing SSL certificates
- **Certificate Generation** - Create self-signed SSL certificates with downloadable files
- **Certificate Chain Analysis** - Validate certificate chains

### 🎯 Advanced Features
- **Real-time Results** - Live network data from authoritative sources
- **Downloadable Files** - Generate and download SSL certificates directly in Claude
- **Error Handling** - Comprehensive error reporting and validation
- **Rate Limiting** - Built-in protection against abuse
- **OAuth Integration** - Secure authentication support

## 🏗️ Architecture

This MCP server is built with:
- **TypeScript** - Type-safe development
- **Modular Design** - Each tool in separate modules for maintainability
- **MCP Protocol Compliance** - Follows official MCP specification
- **Cloudflare Workers** - Serverless deployment for global performance

## 📋 Installation

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Setup
```bash
# Clone the repository
git clone https://github.com/KamranBiglari/mcp-network-tools.git
cd mcp-network-tools

# Install dependencies
npm install

# Build the project
npm run build

# Deploy to Cloudflare Workers (optional)
npm run deploy
```

### Configuration for Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "servers": {
    "network-tools": {
      "command": "node",
      "args": ["path/to/mcp-network-tools/dist/index.js"],
      "env": {}
    }
  }
}
```

Or use the live version:
```json
{
  "servers": {
    "network-tools": {
      "url": "https://network-tools.mcp.cloudcertainty.com/mcp"
    }
  }
}
```

## 🛠️ Usage Examples

![Network Analysis Tools](./screenshots/Screenshot%202025-07-03%20232004.png)

### Generate SSL Certificate
```
@network-tools Generate a self-signed SSL certificate for example.com
```

### Check Domain Information  
```
@network-tools Get WHOIS information for google.com
```

### Scan Ports
```
@network-tools Scan common ports on 192.168.1.1
```

### DNS Lookup
```
@network-tools Look up DNS records for cloudflare.com
```

![SSL Certificate Generation](./screenshots/Screenshot%202025-07-03%20232135.png)

## 🔧 Development

### Project Structure
```
src/
├── index.ts              # Main server entry point
├── tools/                # Individual tool implementations
│   ├── certificate.ts    # SSL certificate generation
│   ├── domain.ts         # Domain WHOIS
│   ├── ip.ts            # IP WHOIS and geolocation
│   ├── nslookup.ts      # DNS queries
│   ├── ping.ts          # Network connectivity
│   ├── portscan.ts      # Port scanning
│   └── types.ts         # Type definitions
└── utils/               # Utility functions
    ├── certificate.ts   # Certificate generation utilities
    └── logger.ts        # Logging utilities
```

### Content Types

This project implements the official MCP content types:
- `text` - Markdown and plain text responses
- `image` - Charts and diagrams (future enhancement)
- `resource` - Downloadable files (certificates, configs)

See [CONTENT_TYPES.md](./CONTENT_TYPES.md) for detailed documentation.

### Adding New Tools

1. Create a new file in `src/tools/`
2. Implement the tool interface from `types.ts`
3. Export from `src/tools/index.ts`
4. Register in `src/index.ts`

Example:
```typescript
export const myTool: ToolDefinition = {
    name: "my_tool",
    description: "Description of what this tool does",
    schema: {
        type: "object",
        properties: {
            target: { type: "string", description: "Target parameter" }
        },
        required: ["target"]
    },
    handler: async (params) => {
        // Implementation
        return {
            content: [{
                type: "text",
                text: "Result"
            }]
        };
    }
};
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 🙏 Acknowledgments

Special thanks to **[James Anderson](https://github.com/JAndersonncfx)** for valuable ideas and contributions to this project.

## 📜 License

MIT License - see [LICENSE](./LICENSE) file for details.

## 🔗 Links

- **Live Demo**: https://network-tools.mcp.cloudcertainty.com/mcp
- **MCP Protocol**: https://modelcontextprotocol.io/
- **Documentation**: https://modelcontextprotocol.io/docs/
- **GitHub**: https://github.com/KamranBiglari/mcp-network-tools

## 📈 Roadmap

- [ ] Network topology visualization
- [ ] SSL certificate monitoring
- [ ] Network performance metrics
- [ ] Integration with more network databases
- [ ] GraphQL API support
- [ ] WebSocket real-time updates

---

Built with ❤️ for the Model Context Protocol community
