// Common types for the application
export interface User {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  avatarUrl?: string;
  createdAt: string;
  updatedAt: string;
  emailVerified: boolean;
}

export interface Task {
  id: number;
  userId: number;
  title: string;
  description?: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
  status: 'TODO' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';
  dueDate?: string;
  createdAt: string;
  updatedAt: string;
  user?: Pick<User, 'firstName' | 'lastName' | 'email'> & { passwordHash?: string };
  comments?: Comment[];
  searchMetadata?: {
    originalQuery?: string;
    sqlQuery?: string;
    executedAt?: string;
    vulnerability?: string;
  };
}

export interface Comment {
  id: number;
  taskId: number;
  userId: number;
  content: string;
  createdAt: string;
  updatedAt: string;
  user?: Pick<User, 'firstName' | 'lastName'>;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
}

export interface ApiError {
  message: string;
  status?: number;
  details?: string;
}

// API Response types
export interface TaskResponse {
  task: Task;
  ownership?: {
    taskOwnerId: number;
    requestUserId: number;
    isOwner: boolean;
    vulnerability?: string;
  };
}

export interface TasksResponse {
  tasks: Task[];
  pagination?: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  dataLeakOccurred?: boolean;
  warning?: string;
}

export interface CommentResponse {
  comment: Comment;
  securityInfo?: {
    contentSanitized: boolean;
    xssVulnerability: boolean;
    rawContentStored: boolean;
    vulnerability?: string;
  };
  xssTestingHints?: {
    basicXSS: string;
    imageXSS: string;
    svgXSS: string;
    iframeXSS: string;
  };
  ownershipInfo?: {
    commentOwnerId: number;
    requestUserId: number;
    isOwner: boolean;
    vulnerability?: string;
  };
  authorizationInfo?: {
    commentOwnerId: number;
    taskOwnerId: number;
    requestUserId: number;
    isCommentOwner: boolean;
    isTaskOwner: boolean;
    authorizationBypassed: boolean;
    vulnerability?: string;
  };
}

export interface CommentsResponse {
  comments: Comment[];
  taskInfo?: {
    id: number;
    userId: number;
    title: string;
  };
  accessInfo?: {
    taskOwnerId: number;
    requestUserId: number;
    isTaskOwner: boolean;
    vulnerability?: string;
  };
}

// Profile and SSRF related types
export interface AvatarUploadRequest {
  imageUrl: string;
  fetchFromUrl: boolean;
}

export interface AvatarUploadResponse {
  success: boolean;
  avatarUrl?: string;
  content?: string;
  metadata?: any;
  internalService?: any;
  message: string;
  warning?: string;
  filePath?: string;
  fetchedFrom?: string;
  exploitationInfo?: {
    awsCredentials?: boolean;
    instanceMetadata?: boolean;
    gcpMetadata?: boolean;
    azureMetadata?: boolean;
  };
  networkInfo?: {
    targetHost?: string;
    detectedPort?: string;
    serviceIdentification?: string;
    responseIndicatesService?: boolean;
  };
  fileInfo?: {
    requestedPath?: string;
    fileTypeDetected?: string;
    contentLength?: number;
    potentiallysensitive?: boolean;
  };
}

export interface TaskImportRequest {
  importUrl: string;
  format?: 'json' | 'csv' | 'xml' | 'txt';
  parseContent?: boolean;
}

export interface TaskImportResponse {
  success: boolean;
  importType: 'cloud_metadata' | 'internal_network_scan' | 'local_file_inclusion' | 'external_url';
  importedTasks?: Task[];
  importedCount?: number;
  data?: any;
  content?: string;
  metadata?: any;
  headers?: any;
  status?: number;
  message: string;
  warning?: string;
  metadataType?: string;
  serviceType?: string;
  port?: string;
  fileType?: string;
  filePath?: string;
  parseErrors?: string[];
  rawResponse?: {
    status: number;
    headers: any;
    dataType: string;
    dataLength: number;
    data: any;
  };
  exploitationInfo?: {
    awsCredentials?: boolean;
    instanceMetadata?: boolean;
    gcpMetadata?: boolean;
    azureMetadata?: boolean;
  };
  networkInfo?: {
    targetHost?: string;
    detectedPort?: string;
    serviceIdentification?: string;
    responseIndicatesService?: boolean;
  };
  fileInfo?: {
    requestedPath?: string;
    fileTypeDetected?: string;
    contentLength?: number;
    potentiallysensitive?: boolean;
  };
}