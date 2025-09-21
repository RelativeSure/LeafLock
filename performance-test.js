#!/usr/bin/env node

/**
 * LeafLock Performance Testing Suite
 *
 * This script performs comprehensive performance testing for the LeafLock application
 * focusing on authentication load, concurrent users, and API performance.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// Configuration
const CONFIG = {
  BASE_URL: 'http://localhost:8080',
  API_BASE: '/api/v1',
  CONCURRENT_USERS: 50,
  REQUESTS_PER_USER: 10,
  TEST_DURATION_MS: 60000, // 1 minute
  RAMP_UP_TIME_MS: 10000,  // 10 seconds
  ADMIN_EMAIL: 'admin@leaflock.app',
  ADMIN_PASSWORD: 'AdminPass123!'
};

// Test results storage
const results = {
  healthChecks: [],
  authTests: [],
  noteOperations: [],
  concurrentTests: [],
  errors: [],
  summary: {}
};

// Utility functions
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const client = options.protocol === 'https:' ? https : http;
    const req = client.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body,
          timing: Date.now() - startTime
        });
      });
    });

    req.on('error', reject);

    const startTime = Date.now();
    if (data) {
      req.write(data);
    }
    req.end();
  });
}

function createUser(email, password) {
  const userData = JSON.stringify({
    email: email,
    password: password
  });

  return makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: `${CONFIG.API_BASE}/auth/register`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(userData)
    }
  }, userData);
}

function loginUser(email, password) {
  const loginData = JSON.stringify({
    email: email,
    password: password
  });

  return makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: `${CONFIG.API_BASE}/auth/login`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(loginData)
    }
  }, loginData);
}

function createNote(token, title, content) {
  const noteData = JSON.stringify({
    title: title,
    content: content,
    folder_id: null,
    tags: ['performance-test']
  });

  return makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: `${CONFIG.API_BASE}/notes`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(noteData),
      'Authorization': `Bearer ${token}`
    }
  }, noteData);
}

function getNotes(token) {
  return makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: `${CONFIG.API_BASE}/notes`,
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
}

function checkHealth() {
  return makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: `${CONFIG.API_BASE}/health`,
    method: 'GET'
  });
}

// Test functions
async function testHealthEndpoint() {
  console.log('🏥 Testing health endpoint...');

  const iterations = 100;
  const timings = [];

  for (let i = 0; i < iterations; i++) {
    try {
      const start = Date.now();
      const response = await checkHealth();
      const duration = Date.now() - start;

      timings.push(duration);
      results.healthChecks.push({
        iteration: i + 1,
        duration: duration,
        status: response.statusCode,
        success: response.statusCode === 200
      });

      if (i % 10 === 0) {
        process.stdout.write(`\r  Progress: ${i + 1}/${iterations}`);
      }
    } catch (error) {
      results.errors.push({
        test: 'health_check',
        iteration: i + 1,
        error: error.message
      });
    }
  }

  const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
  const maxTime = Math.max(...timings);
  const minTime = Math.min(...timings);

  console.log(`\n  ✅ Health checks completed: ${timings.length}/${iterations}`);
  console.log(`  📊 Average response time: ${avgTime.toFixed(2)}ms`);
  console.log(`  📊 Min/Max response time: ${minTime}ms/${maxTime}ms`);

  return { avgTime, maxTime, minTime, successRate: (timings.length / iterations) * 100 };
}

async function testAuthentication() {
  console.log('\n🔐 Testing authentication performance...');

  const testUsers = [];
  const authTimings = [];

  // Create test users
  for (let i = 0; i < 20; i++) {
    const email = `testuser${i}@perftest.com`;
    const password = `TestPass${i}!`;
    testUsers.push({ email, password });
  }

  console.log('  Creating test users...');
  for (let i = 0; i < testUsers.length; i++) {
    try {
      const start = Date.now();
      const response = await createUser(testUsers[i].email, testUsers[i].password);
      const duration = Date.now() - start;

      results.authTests.push({
        operation: 'register',
        user: i + 1,
        duration: duration,
        status: response.statusCode,
        success: response.statusCode === 201
      });

      process.stdout.write(`\r    Progress: ${i + 1}/${testUsers.length}`);
    } catch (error) {
      results.errors.push({
        test: 'auth_register',
        user: i + 1,
        error: error.message
      });
    }
  }

  console.log('\n  Testing login performance...');
  for (let i = 0; i < testUsers.length; i++) {
    try {
      const start = Date.now();
      const response = await loginUser(testUsers[i].email, testUsers[i].password);
      const duration = Date.now() - start;

      authTimings.push(duration);
      results.authTests.push({
        operation: 'login',
        user: i + 1,
        duration: duration,
        status: response.statusCode,
        success: response.statusCode === 200
      });

      process.stdout.write(`\r    Progress: ${i + 1}/${testUsers.length}`);
    } catch (error) {
      results.errors.push({
        test: 'auth_login',
        user: i + 1,
        error: error.message
      });
    }
  }

  const avgAuthTime = authTimings.reduce((a, b) => a + b, 0) / authTimings.length;
  console.log(`\n  ✅ Authentication tests completed`);
  console.log(`  📊 Average login time: ${avgAuthTime.toFixed(2)}ms`);

  return { avgAuthTime, loginCount: authTimings.length };
}

async function testConcurrentLoad() {
  console.log('\n⚡ Testing concurrent load...');

  // First, get admin token
  const adminLogin = await loginUser(CONFIG.ADMIN_EMAIL, CONFIG.ADMIN_PASSWORD);
  const adminToken = JSON.parse(adminLogin.body).access_token;

  async function userSession(userId) {
    const results = {
      userId: userId,
      operations: [],
      errors: []
    };

    try {
      // Create notes
      for (let i = 0; i < CONFIG.REQUESTS_PER_USER; i++) {
        const start = Date.now();
        const response = await createNote(
          adminToken,
          `Concurrent Test Note ${userId}-${i}`,
          `This is test content for user ${userId} note ${i}. Generated at ${new Date().toISOString()}`
        );
        const duration = Date.now() - start;

        results.operations.push({
          operation: 'create_note',
          noteIndex: i,
          duration: duration,
          status: response.statusCode,
          success: response.statusCode === 201
        });
      }

      // Get notes
      const start = Date.now();
      const response = await getNotes(adminToken);
      const duration = Date.now() - start;

      results.operations.push({
        operation: 'get_notes',
        duration: duration,
        status: response.statusCode,
        success: response.statusCode === 200
      });

    } catch (error) {
      results.errors.push({
        operation: 'user_session',
        error: error.message
      });
    }

    return results;
  }

  console.log(`  Starting ${CONFIG.CONCURRENT_USERS} concurrent user sessions...`);

  const userPromises = [];
  for (let i = 0; i < CONFIG.CONCURRENT_USERS; i++) {
    userPromises.push(userSession(i + 1));
  }

  const concurrentResults = await Promise.all(userPromises);

  // Analyze results
  let totalOperations = 0;
  let successfulOperations = 0;
  let totalDuration = 0;

  concurrentResults.forEach(userResult => {
    results.concurrentTests.push(userResult);
    userResult.operations.forEach(op => {
      totalOperations++;
      totalDuration += op.duration;
      if (op.success) successfulOperations++;
    });
  });

  const avgOperationTime = totalDuration / totalOperations;
  const successRate = (successfulOperations / totalOperations) * 100;

  console.log(`  ✅ Concurrent load test completed`);
  console.log(`  📊 Total operations: ${totalOperations}`);
  console.log(`  📊 Success rate: ${successRate.toFixed(2)}%`);
  console.log(`  📊 Average operation time: ${avgOperationTime.toFixed(2)}ms`);

  return { totalOperations, successRate, avgOperationTime };
}

async function testSecurityHeaders() {
  console.log('\n🛡️  Testing security headers...');

  const response = await makeRequest({
    hostname: 'localhost',
    port: 8080,
    path: CONFIG.API_BASE,
    method: 'GET'
  });

  const securityHeaders = {
    'x-content-type-options': response.headers['x-content-type-options'],
    'x-frame-options': response.headers['x-frame-options'],
    'x-xss-protection': response.headers['x-xss-protection'],
    'strict-transport-security': response.headers['strict-transport-security'],
    'content-security-policy': response.headers['content-security-policy'],
    'access-control-allow-origin': response.headers['access-control-allow-origin']
  };

  console.log('  Security headers found:');
  Object.entries(securityHeaders).forEach(([header, value]) => {
    if (value) {
      console.log(`  ✅ ${header}: ${value}`);
    } else {
      console.log(`  ❌ ${header}: Not set`);
    }
  });

  return securityHeaders;
}

async function runPerformanceTests() {
  console.log('🚀 Starting LeafLock Performance Testing Suite\n');
  console.log(`Configuration:
  - Base URL: ${CONFIG.BASE_URL}
  - Concurrent Users: ${CONFIG.CONCURRENT_USERS}
  - Requests per User: ${CONFIG.REQUESTS_PER_USER}
  - Test Duration: ${CONFIG.TEST_DURATION_MS / 1000}s
`);

  const startTime = Date.now();

  try {
    // Run all tests
    const healthResults = await testHealthEndpoint();
    const authResults = await testAuthentication();
    const securityHeaders = await testSecurityHeaders();
    const concurrentResults = await testConcurrentLoad();

    const totalTime = Date.now() - startTime;

    // Generate summary
    results.summary = {
      totalTestTime: totalTime,
      healthCheck: healthResults,
      authentication: authResults,
      concurrentLoad: concurrentResults,
      securityHeaders: securityHeaders,
      totalErrors: results.errors.length,
      timestamp: new Date().toISOString()
    };

    // Display final results
    console.log('\n' + '='.repeat(60));
    console.log('📊 PERFORMANCE TEST RESULTS SUMMARY');
    console.log('='.repeat(60));

    console.log(`\n🏥 Health Check Performance:`);
    console.log(`   Average Response Time: ${healthResults.avgTime.toFixed(2)}ms`);
    console.log(`   Success Rate: ${healthResults.successRate.toFixed(2)}%`);

    console.log(`\n🔐 Authentication Performance:`);
    console.log(`   Average Login Time: ${authResults.avgAuthTime.toFixed(2)}ms`);
    console.log(`   Login Success Count: ${authResults.loginCount}`);

    console.log(`\n⚡ Concurrent Load Performance:`);
    console.log(`   Total Operations: ${concurrentResults.totalOperations}`);
    console.log(`   Success Rate: ${concurrentResults.successRate.toFixed(2)}%`);
    console.log(`   Average Operation Time: ${concurrentResults.avgOperationTime.toFixed(2)}ms`);

    console.log(`\n🛡️  Security:`);
    console.log(`   Security Headers Present: ${Object.values(securityHeaders).filter(v => v).length}/6`);

    console.log(`\n📋 Summary:`);
    console.log(`   Total Test Duration: ${(totalTime / 1000).toFixed(2)}s`);
    console.log(`   Total Errors: ${results.errors.length}`);

    if (results.errors.length > 0) {
      console.log(`\n❌ Error Details:`);
      results.errors.slice(0, 5).forEach((error, index) => {
        console.log(`   ${index + 1}. ${error.test}: ${error.error}`);
      });
      if (results.errors.length > 5) {
        console.log(`   ... and ${results.errors.length - 5} more errors`);
      }
    }

    // Performance benchmarks
    console.log('\n🎯 Performance Benchmarks:');
    if (healthResults.avgTime < 100) {
      console.log('   ✅ Health endpoint response time: Excellent (<100ms)');
    } else if (healthResults.avgTime < 500) {
      console.log('   ⚠️  Health endpoint response time: Good (100-500ms)');
    } else {
      console.log('   ❌ Health endpoint response time: Needs improvement (>500ms)');
    }

    if (authResults.avgAuthTime < 1000) {
      console.log('   ✅ Authentication response time: Excellent (<1s)');
    } else if (authResults.avgAuthTime < 3000) {
      console.log('   ⚠️  Authentication response time: Good (1-3s)');
    } else {
      console.log('   ❌ Authentication response time: Needs improvement (>3s)');
    }

    if (concurrentResults.successRate > 95) {
      console.log('   ✅ Concurrent load success rate: Excellent (>95%)');
    } else if (concurrentResults.successRate > 90) {
      console.log('   ⚠️  Concurrent load success rate: Good (90-95%)');
    } else {
      console.log('   ❌ Concurrent load success rate: Needs improvement (<90%)');
    }

    console.log('\n' + '='.repeat(60));

    return results;

  } catch (error) {
    console.error('❌ Performance testing failed:', error.message);
    results.errors.push({
      test: 'main',
      error: error.message
    });
    return results;
  }
}

// Run the tests if this script is executed directly
if (require.main === module) {
  runPerformanceTests()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 Performance testing suite failed:', error);
      process.exit(1);
    });
}

module.exports = { runPerformanceTests, results };