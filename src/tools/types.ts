import { z } from "zod";

// Content types based on current MCP protocol
export interface TextContent {
    type: "text";
    text: string;
    mimeType?: string; // Optional MIME type for text content
}

export interface ImageContent {
    type: "image";
    data: string; // Base64 encoded
    mimeType: string;
}

export interface ResourceContent {
    type: "resource";
    resource: {
        uri: string;
        mimeType?: string;
        text?: string; // For text-based resources
    };
}

export type ContentItem = TextContent | ImageContent | ResourceContent;

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
