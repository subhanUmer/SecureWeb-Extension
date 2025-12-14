/**
 * Message types for communication between components
 */

export enum MessageType {
  // URL Analysis
  CHECK_URL = "CHECK_URL",
  
  // Statistics
  GET_STATS = "GET_STATS",
  UPDATE_STATS = "UPDATE_STATS",
  
  // Configuration
  CONFIG_UPDATE = "CONFIG_UPDATE",
  GET_CONFIG = "GET_CONFIG",
  
  // Script Blocking
  SCRIPT_BLOCKED = "SCRIPT_BLOCKED",
  
  // Threat Database
  QUERY_THREAT = "QUERY_THREAT",
  ADD_THREAT = "ADD_THREAT",
  
  // User Actions
  USER_PROCEEDED = "USER_PROCEEDED",
  REPORT_FALSE_POSITIVE = "REPORT_FALSE_POSITIVE",
}

export interface Message {
  type: MessageType;
  data?: any;
}

export interface CheckUrlMessage extends Message {
  type: MessageType.CHECK_URL;
  data: {
    url: string;
  };
}

export interface ScriptBlockedMessage extends Message {
  type: MessageType.SCRIPT_BLOCKED;
  data: {
    url: string;
    reason: string;
    pattern: string;
    timestamp: number;
    severity: string;
  };
}

export interface ConfigUpdateMessage extends Message {
  type: MessageType.CONFIG_UPDATE;
  data: {
    isEnabled?: boolean;
    mode?: "strict" | "moderate" | "permissive";
    whitelist?: string[];
  };
}

export interface MessageResponse {
  success: boolean;
  data?: any;
  error?: string;
}
