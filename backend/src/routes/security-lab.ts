import { Router, Request, Response } from 'express';
import { VulnerabilityManager } from '../utils/VulnerabilityManager';
import { authenticateUser } from '../middleware/auth';

const router = Router();

// Global vulnerability manager instance (will be injected)
let vulnerabilityManager: VulnerabilityManager;

export const setVulnerabilityManager = (manager: VulnerabilityManager) => {
  vulnerabilityManager = manager;
};

// Get all vulnerability configurations
router.get('/vulnerabilities', authenticateUser, async (req: Request, res: Response) => {
  try {
    const vulnerabilities = vulnerabilityManager.getVulnerabilityState();
    res.json({
      success: true,
      vulnerabilities
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch vulnerability configurations'
    });
  }
});

// Get specific vulnerability configuration
router.get('/vulnerabilities/:type', authenticateUser, async (req: Request, res: Response) => {
  try {
    const { type } = req.params;
    const config = vulnerabilityManager.getVulnerabilityConfig(type as any);
    
    if (!config) {
      return res.status(404).json({
        success: false,
        error: 'Vulnerability type not found'
      });
    }
    
    res.json({
      success: true,
      vulnerability: config
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch vulnerability configuration'
    });
  }
});

// Toggle vulnerability on/off
router.post('/vulnerabilities/:type/toggle', authenticateUser, async (req: Request, res: Response) => {
  try {
    const { type } = req.params;
    const newState = await vulnerabilityManager.toggleVulnerability(type as any);
    
    res.json({
      success: true,
      message: `Vulnerability ${type} ${newState ? 'enabled' : 'disabled'}`,
      enabled: newState
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to toggle vulnerability'
    });
  }
});

// Test vulnerability with payload
router.post('/vulnerabilities/:type/test', authenticateUser, async (req: Request, res: Response) => {
  try {
    const { type } = req.params;
    const { payload, target } = req.body;
    
    const config = vulnerabilityManager.getVulnerabilityConfig(type as any);
    if (!config) {
      return res.status(404).json({
        success: false,
        error: 'Vulnerability type not found'
      });
    }
    
    // Log the test attempt for educational purposes
    console.log(`Security Lab Test - Type: ${type}, Payload: ${payload}, Target: ${target}`);
    
    // Actually execute the attack against the real endpoints
    const testResult = await executeRealAttack(type, payload, target, config, req);
    
    res.json(testResult);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to test vulnerability'
    });
  }
});

// Function to execute real attacks against vulnerable endpoints
async function executeRealAttack(type: string, payload: string, target: string, config: any, req: Request) {
  const baseUrl = `http://localhost:${process.env.PORT || 3001}`;
  const token = req.headers.authorization;
  
  let attackResult = {
    success: true,
    vulnerabilityType: type,
    payload,
    target,
    enabled: config.enabled,
    result: 'SECURE',
    timestamp: new Date().toISOString(),
    description: '',
    actualResponse: null as any,
    attackSucceeded: false
  };

  if (!config.enabled) {
    attackResult.description = 'Vulnerability is disabled. Attack was blocked by secure implementation.';
    return attackResult;
  }

  try {
    switch (type) {
      case 'sqlInjection':
        attackResult = await testSQLInjection(baseUrl, token, payload, target, attackResult);
        break;
      case 'xss':
        attackResult = await testXSS(baseUrl, token, payload, target, attackResult);
        break;
      case 'idor':
        attackResult = await testIDOR(baseUrl, token, payload, target, attackResult);
        break;
      case 'sessionManagement':
        attackResult = await testSessionManagement(baseUrl, token, payload, target, attackResult);
        break;
      case 'ssrfLfi':
        attackResult = await testSSRFLFI(baseUrl, token, payload, target, attackResult);
        break;
      default:
        attackResult.description = 'Unknown vulnerability type';
    }
  } catch (error) {
    attackResult.description = `Attack execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
    attackResult.result = 'ERROR';
  }

  return attackResult;
}

async function testSQLInjection(baseUrl: string, token: string | undefined, payload: string, target: string, result: any) {
  const axios = require('axios');
  
  try {
    const response = await axios.get(`${baseUrl}/api/tasks/simple-search`, {
      params: { query: payload },
      headers: token ? { Authorization: token } : {},
      timeout: 5000
    });
    
    result.actualResponse = response.data;
    
    // Check if SQL injection was successful
    if (response.data && response.data.results && Array.isArray(response.data.results)) {
      // Look for signs of successful SQL injection
      const hasUnexpectedData = response.data.results.some((item: any) => 
        item.email || item.password_hash || item.username || 
        (typeof item === 'object' && Object.keys(item).length > 10)
      );
      
      if (hasUnexpectedData || response.data.results.length > 0) {
        result.result = 'VULNERABLE';
        result.attackSucceeded = true;
        result.description = `SQL Injection successful! Retrieved ${response.data.results.length} records with sensitive data including password hashes.`;
      } else {
        result.result = 'VULNERABLE';
        result.attackSucceeded = false;
        result.description = `SQL Injection payload was processed but didn't return sensitive data. The vulnerability exists but payload may need refinement.`;
      }
    } else {
      result.result = 'SECURE';
      result.description = 'SQL Injection blocked by parameterized queries or input validation.';
    }
  } catch (error: any) {
    if (error.response?.status === 500 && error.response?.data?.error) {
      result.result = 'VULNERABLE';
      result.attackSucceeded = true;
      result.description = `SQL Injection successful! Database error exposed: "${error.response.data.error}"`;
      result.actualResponse = error.response.data;
    } else {
      result.result = 'SECURE';
      result.description = 'SQL Injection blocked or endpoint not accessible.';
    }
  }
  
  return result;
}

async function testXSS(baseUrl: string, token: string | undefined, payload: string, target: string, result: any) {
  const axios = require('axios');
  
  try {
    const taskId = target || '1';
    
    // First, try to get existing tasks to find a valid task ID
    let validTaskId = taskId;
    try {
      const tasksResponse = await axios.get(`${baseUrl}/api/tasks`, {
        headers: token ? { Authorization: token } : {},
        timeout: 5000
      });
      
      if (tasksResponse.data && tasksResponse.data.length > 0) {
        validTaskId = tasksResponse.data[0].id.toString();
      }
    } catch (taskError) {
      // If we can't get tasks, we'll try to create a test task
      try {
        const createTaskResponse = await axios.post(`${baseUrl}/api/tasks`, {
          title: 'XSS Test Task',
          description: 'Temporary task for XSS testing',
          priority: 'LOW'
        }, {
          headers: token ? { Authorization: token } : {},
          timeout: 5000
        });
        
        if (createTaskResponse.data && createTaskResponse.data.id) {
          validTaskId = createTaskResponse.data.id.toString();
        }
      } catch (createError) {
        // If we can't create a task either, we'll proceed with the original ID
        console.log('Could not create test task, using original target ID');
      }
    }
    
    // Test XSS by posting a comment with the payload
    const response = await axios.post(`${baseUrl}/api/comments/task/${validTaskId}`, {
      content: payload
    }, {
      headers: token ? { Authorization: token } : {},
      timeout: 5000
    });
    
    result.actualResponse = response.data;
    
    if (response.status === 200 || response.status === 201) {
      // Check if the payload was stored without sanitization
      const getResponse = await axios.get(`${baseUrl}/api/comments/task/${validTaskId}`, {
        headers: token ? { Authorization: token } : {}
      });
      
      const comments = getResponse.data.comments || [];
      const hasXSSPayload = comments.some((comment: any) => 
        comment.content && (
          comment.content.includes('<script>') || 
          comment.content.includes('javascript:') ||
          comment.content.includes('onerror=') ||
          comment.content.includes('<img') ||
          comment.content === payload
        )
      );
      
      if (hasXSSPayload) {
        result.result = 'VULNERABLE';
        result.attackSucceeded = true;
        result.description = `XSS payload stored successfully! The payload "${payload}" was saved without sanitization and will execute when the comment is viewed. Task ID used: ${validTaskId}`;
      } else {
        result.result = 'SECURE';
        result.description = 'XSS payload was sanitized or blocked by input validation.';
      }
    }
  } catch (error: any) {
    if (error.response?.status === 404) {
      result.result = 'ERROR';
      result.description = `XSS test failed: Task not found (404). Try creating a task first or ensure you're logged in. Error: ${error.message}`;
    } else {
      result.result = 'SECURE';
      result.description = `XSS attack blocked: ${error.message}`;
    }
  }
  
  return result;
}

async function testIDOR(baseUrl: string, token: string | undefined, payload: string, target: string, result: any) {
  const axios = require('axios');
  
  try {
    let taskIdToTest = target || payload;
    
    // If no specific task ID provided, try to find existing tasks
    if (!taskIdToTest || taskIdToTest === 'Increment task ID: /api/tasks/123 → /api/tasks/124') {
      try {
        // Get all tasks to find existing task IDs
        const tasksResponse = await axios.get(`${baseUrl}/api/tasks`, {
          headers: token ? { Authorization: token } : {},
          timeout: 5000
        });
        
        if (tasksResponse.data && tasksResponse.data.tasks && tasksResponse.data.tasks.length > 0) {
          // Use the first task ID and increment it to test IDOR
          const firstTaskId = tasksResponse.data.tasks[0].id;
          taskIdToTest = (firstTaskId + 1).toString();
          
          // Also try some other task IDs that might belong to other users
          const testIds = [firstTaskId + 1, firstTaskId + 2, firstTaskId - 1, 1, 2, 3, 999];
          
          for (const testId of testIds) {
            try {
              const testResponse = await axios.get(`${baseUrl}/api/tasks/${testId}`, {
                headers: token ? { Authorization: token } : {},
                timeout: 5000
              });
              
              if (testResponse.status === 200 && testResponse.data && testResponse.data.task) {
                const task = testResponse.data.task;
                const ownership = testResponse.data.ownership;
                
                // Check if we accessed a task that doesn't belong to us
                if (ownership && !ownership.isOwner) {
                  result.result = 'VULNERABLE';
                  result.attackSucceeded = true;
                  result.description = `IDOR successful! Accessed task ${testId} ("${task.title}") owned by user ${ownership.taskOwnerId} while logged in as user ${ownership.requestUserId}. The vulnerability allows accessing other users' tasks.`;
                  result.actualResponse = testResponse.data;
                  return result;
                }
              }
            } catch (testError) {
              // Continue testing other IDs
              continue;
            }
          }
        }
      } catch (tasksError) {
        // If we can't get tasks, use default ID
        taskIdToTest = '999';
      }
    }
    
    // Test IDOR by trying to access the specified task
    const response = await axios.get(`${baseUrl}/api/tasks/${taskIdToTest}`, {
      headers: token ? { Authorization: token } : {},
      timeout: 5000
    });
    
    result.actualResponse = response.data;
    
    if (response.status === 200 && response.data && response.data.task) {
      const ownership = response.data.ownership;
      
      if (ownership && !ownership.isOwner) {
        result.result = 'VULNERABLE';
        result.attackSucceeded = true;
        result.description = `IDOR successful! Accessed task ${taskIdToTest} ("${response.data.task.title}") owned by user ${ownership.taskOwnerId} while logged in as user ${ownership.requestUserId}.`;
      } else if (ownership && ownership.isOwner) {
        result.result = 'INCONCLUSIVE';
        result.attackSucceeded = false;
        result.description = `Accessed task ${taskIdToTest} but it belongs to the current user. Try testing with a task ID that belongs to another user.`;
      } else {
        result.result = 'VULNERABLE';
        result.attackSucceeded = true;
        result.description = `IDOR successful! Accessed task ${taskIdToTest} without proper authorization checks.`;
      }
    }
  } catch (error: any) {
    if (error.response?.status === 403) {
      result.result = 'SECURE';
      result.description = 'IDOR blocked by proper authorization checks (403 Forbidden).';
    } else if (error.response?.status === 404) {
      result.result = 'INCONCLUSIVE';
      result.description = `Task ${target || payload || '999'} not found (404). The IDOR vulnerability may exist but the task ID doesn't exist. Try with existing task IDs.`;
    } else {
      result.result = 'ERROR';
      result.description = `IDOR test failed: ${error.message}`;
    }
  }
  
  return result;
}

async function testSessionManagement(baseUrl: string, token: string | undefined, payload: string, target: string, result: any) {
  const axios = require('axios');
  
  try {
    let vulnerabilities = [];
    let testResults = [];
    
    // Test 1: Check session info endpoint (should not be exposed)
    try {
      const sessionInfoResponse = await axios.get(`${baseUrl}/api/auth/session-info`);
      if (sessionInfoResponse.status === 200) {
        vulnerabilities.push('Session configuration exposed via /api/auth/session-info');
        testResults.push({
          test: 'Session Info Exposure',
          result: 'VULNERABLE',
          details: 'Endpoint exposes JWT secret and configuration'
        });
      }
    } catch (error) {
      testResults.push({
        test: 'Session Info Exposure',
        result: 'SECURE',
        details: 'Session info endpoint not accessible'
      });
    }
    
    // Test 2: Token validation endpoint exposes secrets
    if (token) {
      try {
        const validateResponse = await axios.post(`${baseUrl}/api/auth/validate`, {
          token: token
        });
        
        if (validateResponse.status === 200 && validateResponse.data.tokenDetails) {
          const tokenDetails = validateResponse.data.tokenDetails;
          if (tokenDetails.secret) {
            vulnerabilities.push('JWT secret exposed in token validation');
            testResults.push({
              test: 'Token Validation Secret Exposure',
              result: 'VULNERABLE',
              details: `JWT secret exposed: ${tokenDetails.secret}`
            });
          }
        }
      } catch (error) {
        // Even error responses might expose secrets
        if (error.response?.data?.secret) {
          vulnerabilities.push('JWT secret exposed in validation errors');
          testResults.push({
            test: 'Token Validation Secret Exposure',
            result: 'VULNERABLE',
            details: 'JWT secret exposed in error responses'
          });
        }
      }
    }
    
    // Test 3: Check if logout properly invalidates tokens
    if (token) {
      try {
        // Call logout
        const logoutResponse = await axios.post(`${baseUrl}/api/auth/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (logoutResponse.data.tokenInfo && logoutResponse.data.tokenInfo.stillValid) {
          vulnerabilities.push('Logout does not invalidate tokens');
          testResults.push({
            test: 'Token Invalidation on Logout',
            result: 'VULNERABLE',
            details: 'Token remains valid after logout'
          });
        }
        
        // Try to use token after logout
        const testAfterLogout = await axios.get(`${baseUrl}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (testAfterLogout.status === 200) {
          vulnerabilities.push('Token still valid after logout');
          testResults.push({
            test: 'Post-Logout Token Usage',
            result: 'VULNERABLE',
            details: 'Token can still be used after logout'
          });
        }
      } catch (error) {
        if (error.response?.status === 401) {
          testResults.push({
            test: 'Post-Logout Token Usage',
            result: 'SECURE',
            details: 'Token properly invalidated after logout'
          });
        }
      }
    }
    
    // Test 4: Check token refresh with expired tokens
    if (token) {
      try {
        const refreshResponse = await axios.post(`${baseUrl}/api/auth/refresh`, {}, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (refreshResponse.data.refreshInfo && refreshResponse.data.refreshInfo.vulnerability) {
          vulnerabilities.push('Insecure token refresh mechanism');
          testResults.push({
            test: 'Token Refresh Security',
            result: 'VULNERABLE',
            details: refreshResponse.data.refreshInfo.vulnerability
          });
        }
      } catch (error) {
        // Refresh might fail, which could be secure
        testResults.push({
          test: 'Token Refresh Security',
          result: 'INCONCLUSIVE',
          details: 'Token refresh failed or not implemented'
        });
      }
    }
    
    // Test 5: Decode token client-side (if payload contains this instruction)
    if (payload && payload.includes('Decode JWT token client-side') && token) {
      try {
        // Simulate client-side token decoding
        const tokenParts = token.split('.');
        if (tokenParts.length === 3) {
          const payload_decoded = JSON.parse(atob(tokenParts[1]));
          vulnerabilities.push('JWT payload can be decoded client-side');
          testResults.push({
            test: 'Client-side Token Decoding',
            result: 'VULNERABLE',
            details: `Token payload exposed: userId=${payload_decoded.userId}, email=${payload_decoded.email}, exp=${new Date(payload_decoded.exp * 1000).toISOString()}`
          });
        }
      } catch (error) {
        testResults.push({
          test: 'Client-side Token Decoding',
          result: 'ERROR',
          details: 'Failed to decode token payload'
        });
      }
    }
    
    // Determine overall result
    if (vulnerabilities.length > 0) {
      result.result = 'VULNERABLE';
      result.attackSucceeded = true;
      result.description = `Session management vulnerabilities detected: ${vulnerabilities.join(', ')}. Found ${vulnerabilities.length} security issues.`;
    } else {
      result.result = 'SECURE';
      result.attackSucceeded = false;
      result.description = 'No session management vulnerabilities detected in the tested endpoints.';
    }
    
    result.actualResponse = {
      vulnerabilities,
      testResults,
      summary: {
        totalTests: testResults.length,
        vulnerableTests: testResults.filter(t => t.result === 'VULNERABLE').length,
        secureTests: testResults.filter(t => t.result === 'SECURE').length
      }
    };
    
  } catch (error: any) {
    result.result = 'ERROR';
    result.description = `Session management test failed: ${error.message}`;
  }
  
  return result;
}

async function testSSRFLFI(baseUrl: string, token: string | undefined, payload: string, target: string, result: any) {
  const axios = require('axios');
  
  try {
    // Test SSRF/LFI through file upload or URL fetching
    const response = await axios.post(`${baseUrl}/api/users/avatar`, {
      avatarUrl: payload
    }, {
      headers: token ? { Authorization: token } : {},
      timeout: 5000
    });
    
    result.actualResponse = response.data;
    
    if (response.status === 200) {
      result.result = 'VULNERABLE';
      result.attackSucceeded = true;
      result.description = `SSRF/LFI successful! Server made request to: ${payload}`;
    }
  } catch (error: any) {
    if (error.response?.data?.error?.includes('ENOTFOUND') || 
        error.response?.data?.error?.includes('ECONNREFUSED')) {
      result.result = 'VULNERABLE';
      result.attackSucceeded = true;
      result.description = `SSRF confirmed! Server attempted to connect to ${payload} (connection failed but SSRF vulnerability exists).`;
    } else {
      result.result = 'SECURE';
      result.description = 'SSRF/LFI blocked by input validation or URL filtering.';
    }
  }
  
  return result;
}

// Get attack history (for educational tracking)
router.get('/attack-history', authenticateUser, async (req: Request, res: Response) => {
  try {
    // This would typically come from a database or log system
    // For now, return mock data for demonstration
    const mockHistory = [
      {
        id: 1,
        vulnerabilityType: 'sqlInjection',
        payload: "' UNION SELECT id, email FROM users--",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        result: 'VULNERABLE',
        success: true
      },
      {
        id: 2,
        vulnerabilityType: 'xss',
        payload: "<script>alert('XSS')</script>",
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        result: 'VULNERABLE',
        success: true
      },
      {
        id: 3,
        vulnerabilityType: 'idor',
        payload: 'Direct object reference to task ID 123',
        timestamp: new Date(Date.now() - 900000).toISOString(),
        result: 'SECURE',
        success: false
      }
    ];
    
    res.json({
      success: true,
      history: mockHistory
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch attack history'
    });
  }
});

// Real-time code injection endpoint (for hot-reloading demonstration)
router.post('/inject-code', authenticateUser, async (req: Request, res: Response) => {
  try {
    const { vulnerabilityType, codeType } = req.body; // codeType: 'vulnerable' | 'secure'
    
    // This is a simulation of hot code injection
    // In a real implementation, this would dynamically replace route handlers
    console.log(`Code injection simulation - Type: ${vulnerabilityType}, Code: ${codeType}`);
    
    res.json({
      success: true,
      message: `Code injection simulated for ${vulnerabilityType}`,
      injectedCode: codeType,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to inject code'
    });
  }
});

export default router;