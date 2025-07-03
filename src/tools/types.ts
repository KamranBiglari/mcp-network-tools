import { z } from "zod";

// Content types based on MCP protocol discussion
export interface TextContent {
    type?: "text"; // For backwards compatibility
    mimeType?: string; // Defaults to "text/plain"
    text: string;
    uri?: string; // Optional URI for resource reference
}

export interface BlobContent {
    type?: "blob"; // For backwards compatibility  
    mimeType: string;
    blob: string; // Base64 encoded data
    uri?: string; // Optional URI for resource reference
}

export type ContentItem = TextContent | BlobContent;

export interface ToolResponse {
    content: Array<ContentItem>;
    isError?: boolean;
}

export interface ToolDefinition {
    name: string;
    description: string;
    schema: object;
    handler: (params: any) => Promise<ToolResponse>;
}
