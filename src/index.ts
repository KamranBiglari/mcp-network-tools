import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { 
    domainTool, 
    tldTool, 
    asnTool, 
    ipTool, 
    nslookupTool, 
    pingTool, 
    portscanTool,
    certificateTool,
    sslInfoTool,
    geolocateIpTool,
    cidrToRangeTool,
    macLookupTool
} from './tools';
import { registerTool } from './tools/registry';

// Type definitions
interface Env {
    // Add any environment variables here
}

// Define our MCP agent with tools
export class MyMCP extends McpAgent {
    server = new McpServer({
        name: "mcp-whois",
        version: "1.0.0",
        description: "MCP Server for Network Tools",
        baseUrl: "https://network-tool.mcp.cloudcertainty.com",
        author: "Kamran Biglari",
        authorUrl: "https://github.com/KamranBiglari"
    });

    async init() {
        // Register all tools using the new modular structure
        registerTool(this.server, domainTool);
        registerTool(this.server, tldTool);
        registerTool(this.server, asnTool);
        registerTool(this.server, ipTool);
        registerTool(this.server, nslookupTool);
        registerTool(this.server, pingTool);
        registerTool(this.server, portscanTool);
        registerTool(this.server, certificateTool);
        registerTool(this.server, sslInfoTool);
        registerTool(this.server, geolocateIpTool);
        registerTool(this.server, cidrToRangeTool);
        registerTool(this.server, macLookupTool);
        
        // Note: Additional tools like traceroute, etc.
        // can be added here as they are implemented
    }
}

// Helper function to get the base URL from the request
function getBaseUrl(request: Request): string {
    const url = new URL(request.url);
    return `https://${url.host}`;
}

// OAuth Authorization Server Discovery Response
function createOAuthAuthorizationServerResponse(baseUrl: string) {
    return {
        "issuer": baseUrl,
        "authorization_endpoint": `${baseUrl}/oauth/authorize`,
        "token_endpoint": `${baseUrl}/oauth/token`,
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "response_types_supported": ["code", "token"],
        "grant_types_supported": ["authorization_code", "client_credentials", "implicit"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "scopes_supported": ["read", "write", "openid"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        // Dynamic Client Registration support
        "registration_endpoint": `${baseUrl}/oauth/register`,
        "registration_endpoint_auth_methods_supported": ["none"],
        // Indicate this is an authless server
        "authless": true,
        "require_authentication": false
    };
}

// OAuth Protected Resource Discovery Response
function createOAuthProtectedResourceResponse(baseUrl: string) {
    return {
        "resource": baseUrl,
        "authorization_servers": [baseUrl],
        "scopes_supported": ["read", "write"],
        "bearer_methods_supported": ["header", "query"],
        // Indicate no authentication required
        "authless": true,
        "require_authentication": false,
        "token_validation": "none",
    };
}

// Mock OAuth Token Response
function createMockTokenResponse() {
    return {
        "access_token": "authless-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read write"
    };
}

// Mock Client Registration Response
function createClientRegistrationResponse() {
    return {
        "client_id": "authless-client",
        "client_secret": "authless-secret",
        "client_id_issued_at": Math.floor(Date.now() / 1000),
        "client_secret_expires_at": 0, // Never expires
        "redirect_uris": [],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "client_credentials"],
        "response_types": ["code"],
        "scope": "read write",
    };
}

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext) {
        const url = new URL(request.url);
        const baseUrl = getBaseUrl(request);

        // OAuth Authorization Server Discovery Endpoint
        if (url.pathname === "/.well-known/oauth-authorization-server") {
            return new Response(
                JSON.stringify(createOAuthAuthorizationServerResponse(baseUrl), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // OAuth Protected Resource Discovery Endpoint
        if (url.pathname === "/.well-known/oauth-protected-resource") {
            return new Response(
                JSON.stringify(createOAuthProtectedResourceResponse(baseUrl), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Authorization Endpoint
        if (url.pathname === "/oauth/authorize") {
            const redirectUri = url.searchParams.get("redirect_uri");
            const state = url.searchParams.get("state");
            const clientId = url.searchParams.get("client_id");
            const responseType = url.searchParams.get("response_type");
            
            if (redirectUri) {
                // Generate a mock authorization code
                const authCode = `mock_auth_code_${Date.now()}_${Math.random().toString(36).substring(2)}`;
                
                // Build redirect URL with authorization code
                const redirectUrl = new URL(redirectUri);
                redirectUrl.searchParams.set("code", authCode);
                if (state) {
                    redirectUrl.searchParams.set("state", state);
                }
                
                return Response.redirect(redirectUrl.toString());
            }
            
            // If no redirect_uri, return the authorization code directly
            const authCode = `mock_auth_code_${Date.now()}_${Math.random().toString(36).substring(2)}`;
            return new Response(
                JSON.stringify({
                    authorization_code: authCode,
                    client_id: clientId,
                    response_type: responseType,
                    message: "Copy this authorization code and return to the Auth Debugger"
                }, null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Token Endpoint
        if (url.pathname === "/oauth/token") {
            // Handle authorization code exchange
            if (request.method === "POST") {
                const formData = await request.formData();
                const code = formData.get("code");
                const grantType = formData.get("grant_type");
                
                if (grantType === "authorization_code" && code) {
                    // Validate the authorization code (in a real implementation)
                    if (code.toString().startsWith("mock_auth_code_")) {
                        return new Response(
                            JSON.stringify(createMockTokenResponse(), null, 2),
                            {
                                headers: {
                                    "Content-Type": "application/json",
                                    "Access-Control-Allow-Origin": "*",
                                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                                },
                            }
                        );
                    } else {
                        return new Response(
                            JSON.stringify({ error: "invalid_grant", error_description: "Invalid authorization code" }, null, 2),
                            {
                                status: 400,
                                headers: {
                                    "Content-Type": "application/json",
                                    "Access-Control-Allow-Origin": "*",
                                },
                            }
                        );
                    }
                }
            }
            
            // Default token response for other grant types
            return new Response(
                JSON.stringify(createMockTokenResponse(), null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                }
            );
        }

        // Mock OAuth Client Registration Endpoint
        if (url.pathname === "/oauth/register") {
            // Handle both GET and POST for client registration
            if (request.method === "POST" || request.method === "GET") {
                return new Response(
                    JSON.stringify(createClientRegistrationResponse(), null, 2),
                    {
                        headers: {
                            "Content-Type": "application/json",
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                            "Access-Control-Allow-Headers": "Content-Type, Authorization",
                        },
                    }
                );
            }
        }

        // Health check endpoint
        if (url.pathname === "/health") {
            return new Response(
                JSON.stringify({
                    status: "ok",
                    authless: true,
                    timestamp: new Date().toISOString(),
                    server: "mcp-network-tools",
                }, null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                }
            );
        }

        // Root endpoint with server info
        if (url.pathname === "/") {
            return new Response(
                JSON.stringify({
                    name: "mcp-network-tools",
                    version: "1.0.0",
                    authless: true,
                    endpoints: {
                        mcp: "/mcp",
                        sse: "/sse",
                        health: "/health",
                        oauth_authorization_server: "/.well-known/oauth-authorization-server",
                        oauth_protected_resource: "/.well-known/oauth-protected-resource",
                        oauth_authorize: "/oauth/authorize",
                        oauth_token: "/oauth/token"
                    }
                }, null, 2),
                {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                    },
                }
            );
        }

        // Handle CORS preflight requests
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                },
            });
        }

        // Existing MCP endpoints
        if (url.pathname === "/sse" || url.pathname === "/sse/message") {
            return MyMCP.serveSSE("/sse").fetch(request, env, ctx);
        }

        if (url.pathname === "/mcp") {
            return MyMCP.serve("/mcp").fetch(request, env, ctx);
        }

        return new Response("Not found", { status: 404 });
    },
};
