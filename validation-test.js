#!/usr/bin/env node

/**
 * LeafLock Deployment Validation Suite
 *
 * This script performs comprehensive validation for production readiness
 * including security, performance, and configuration checks.
 */

const http = require('http');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Configuration
const CONFIG = {
  BASE_URL: 'http://localhost:8080',
  API_BASE: '/api/v1',
  FRONTEND_URL: 'http://localhost:3000',
  ADMIN_EMAIL: 'admin@leaflock.app',
  ADMIN_PASSWORD: 'AdminPass123!'
};

// Test results storage
const validationResults = {
  connectivity: {},
  security: {},
  authentication: {},
  environment: {},
  performance: {},
  docker: {},
  errors: []
};

// Utility functions
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
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

// Test functions
async function testConnectivity() {
  console.log('🌐 Testing connectivity...');

  const tests = [
    { name: 'Backend Health', url: '/api/v1/health' },
    { name: 'Backend API Root', url: '/api/v1' },
    { name: 'Frontend', url: '/', frontend: true }
  ];

  for (const test of tests) {
    try {
      const options = {
        hostname: 'localhost',
        port: test.frontend ? 3000 : 8080,
        path: test.url,
        method: 'GET',
        timeout: 5000
      };

      const response = await makeRequest(options);

      validationResults.connectivity[test.name] = {
        status: 'success',
        statusCode: response.statusCode,
        responseTime: response.timing,
        accessible: response.statusCode < 400
      };

      console.log(`  ✅ ${test.name}: ${response.statusCode} (${response.timing}ms)`);
    } catch (error) {
      validationResults.connectivity[test.name] = {
        status: 'error',
        error: error.message
      };
      console.log(`  ❌ ${test.name}: ${error.message}`);
    }
  }
}

async function testSecurity() {
  console.log('\n🛡️  Testing security measures...');

  try {
    // Test security headers
    const response = await makeRequest({
      hostname: 'localhost',
      port: 8080,
      path: '/api/v1/health',
      method: 'GET'
    });

    const securityHeaders = {
      'X-Content-Type-Options': response.headers['x-content-type-options'],
      'X-Frame-Options': response.headers['x-frame-options'],
      'X-XSS-Protection': response.headers['x-xss-protection'],
      'Content-Security-Policy': response.headers['content-security-policy']
    };

    validationResults.security.headers = securityHeaders;

    let headerScore = 0;
    Object.entries(securityHeaders).forEach(([header, value]) => {
      if (value) {
        headerScore++;
        console.log(`  ✅ ${header}: Present`);
      } else {
        console.log(`  ❌ ${header}: Missing`);
      }
    });

    validationResults.security.headerScore = `${headerScore}/${Object.keys(securityHeaders).length}`;

    // Test CORS
    const corsResponse = await makeRequest({
      hostname: 'localhost',
      port: 8080,
      path: '/api/v1/health',
      method: 'OPTIONS',
      headers: {
        'Origin': 'http://localhost:3000',
        'Access-Control-Request-Method': 'GET'
      }
    });

    const corsHeaders = {
      'Access-Control-Allow-Origin': corsResponse.headers['access-control-allow-origin'],
      'Access-Control-Allow-Methods': corsResponse.headers['access-control-allow-methods'],
      'Access-Control-Allow-Headers': corsResponse.headers['access-control-allow-headers']
    };

    validationResults.security.cors = corsHeaders;
    console.log(`  🌐 CORS configured: ${corsHeaders['Access-Control-Allow-Origin'] ? 'Yes' : 'No'}`);

    // Test rate limiting
    console.log('  🔄 Testing rate limiting...');
    let rateLimitHit = false;
    for (let i = 0; i < 200; i++) {
      try {
        const testResponse = await makeRequest({
          hostname: 'localhost',
          port: 8080,
          path: '/api/v1/debug/metrics',
          method: 'GET'
        });

        if (testResponse.statusCode === 429) {
          rateLimitHit = true;
          break;
        }
      } catch (error) {
        if (error.code === 'ECONNRESET') {
          rateLimitHit = true;
          break;
        }
      }
    }

    validationResults.security.rateLimiting = rateLimitHit;
    console.log(`  ⚡ Rate limiting active: ${rateLimitHit ? 'Yes' : 'No'}`);

  } catch (error) {
    validationResults.errors.push({
      test: 'security',
      error: error.message
    });
    console.log(`  ❌ Security test error: ${error.message}`);
  }
}

async function testAuthentication() {
  console.log('\n🔐 Testing authentication system...');

  try {
    // Test admin login
    const loginData = JSON.stringify({
      email: CONFIG.ADMIN_EMAIL,
      password: CONFIG.ADMIN_PASSWORD
    });

    const loginResponse = await makeRequest({
      hostname: 'localhost',
      port: 8080,
      path: '/api/v1/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(loginData)
      }
    }, loginData);

    if (loginResponse.statusCode === 200) {
      const loginResult = JSON.parse(loginResponse.body);
      validationResults.authentication.adminLogin = {
        status: 'success',
        hasToken: !!loginResult.access_token,
        responseTime: loginResponse.timing
      };
      console.log(`  ✅ Admin login: Success (${loginResponse.timing}ms)`);

      // Test protected endpoint
      if (loginResult.access_token) {
        const protectedResponse = await makeRequest({
          hostname: 'localhost',
          port: 8080,
          path: '/api/v1/notes',
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${loginResult.access_token}`
          }
        });

        validationResults.authentication.protectedAccess = {
          status: protectedResponse.statusCode === 200 ? 'success' : 'error',
          statusCode: protectedResponse.statusCode,
          responseTime: protectedResponse.timing
        };

        console.log(`  ✅ Protected endpoint access: ${protectedResponse.statusCode} (${protectedResponse.timing}ms)`);
      }
    } else {
      validationResults.authentication.adminLogin = {
        status: 'error',
        statusCode: loginResponse.statusCode,
        response: loginResponse.body
      };
      console.log(`  ❌ Admin login failed: ${loginResponse.statusCode}`);
    }

    // Test invalid credentials
    const invalidLogin = await makeRequest({
      hostname: 'localhost',
      port: 8080,
      path: '/api/v1/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    }, JSON.stringify({
      email: 'invalid@example.com',
      password: 'wrongpassword'
    }));

    validationResults.authentication.invalidLogin = {
      statusCode: invalidLogin.statusCode,
      rejected: invalidLogin.statusCode === 401
    };

    console.log(`  🔒 Invalid login rejection: ${invalidLogin.statusCode === 401 ? 'Working' : 'Not working'}`);

  } catch (error) {
    validationResults.errors.push({
      test: 'authentication',
      error: error.message
    });
    console.log(`  ❌ Authentication test error: ${error.message}`);
  }
}

async function testEnvironment() {
  console.log('\n🌍 Testing environment configuration...');

  try {
    // Check Docker containers
    const { stdout: containers } = await execAsync('docker compose ps --format json');
    const containerList = containers.trim().split('\n').map(line => JSON.parse(line));

    validationResults.environment.containers = containerList.map(container => ({
      name: container.Service,
      status: container.State,
      healthy: container.State === 'running'
    }));

    containerList.forEach(container => {
      const status = container.State === 'running' ? '✅' : '❌';
      console.log(`  ${status} ${container.Service}: ${container.State}`);
    });

    // Check environment variables
    const envVars = [
      'POSTGRES_PASSWORD',
      'REDIS_PASSWORD',
      'JWT_SECRET',
      'SERVER_ENCRYPTION_KEY',
      'CORS_ORIGINS'
    ];

    console.log('  📋 Environment variables:');
    for (const envVar of envVars) {
      // Check if env var exists in .env file
      try {
        const { stdout } = await execAsync(`grep "^${envVar}=" .env`);
        const hasValue = stdout.trim().split('=')[1] && stdout.trim().split('=')[1] !== '';
        console.log(`    ${hasValue ? '✅' : '❌'} ${envVar}: ${hasValue ? 'Set' : 'Not set'}`);
        validationResults.environment[envVar] = hasValue;
      } catch (error) {
        console.log(`    ❌ ${envVar}: Not found in .env`);
        validationResults.environment[envVar] = false;
      }
    }

  } catch (error) {
    validationResults.errors.push({
      test: 'environment',
      error: error.message
    });
    console.log(`  ❌ Environment test error: ${error.message}`);
  }
}

async function testPerformanceBasics() {
  console.log('\n⚡ Testing basic performance...');

  try {
    // Test health endpoint response time
    const iterations = 10;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      const response = await makeRequest({
        hostname: 'localhost',
        port: 8080,
        path: '/api/v1/health',
        method: 'GET'
      });
      timings.push(Date.now() - start);
    }

    const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
    const maxTime = Math.max(...timings);

    validationResults.performance.healthEndpoint = {
      averageResponseTime: avgTime,
      maxResponseTime: maxTime,
      iterations: iterations
    };

    console.log(`  📊 Health endpoint avg: ${avgTime.toFixed(2)}ms (max: ${maxTime}ms)`);

    // Performance rating
    if (avgTime < 50) {
      console.log('  ✅ Response time: Excellent');
    } else if (avgTime < 200) {
      console.log('  ⚠️  Response time: Good');
    } else {
      console.log('  ❌ Response time: Needs improvement');
    }

  } catch (error) {
    validationResults.errors.push({
      test: 'performance',
      error: error.message
    });
    console.log(`  ❌ Performance test error: ${error.message}`);
  }
}

async function generateReport() {
  console.log('\n' + '='.repeat(80));
  console.log('📋 DEPLOYMENT READINESS REPORT');
  console.log('='.repeat(80));

  // Connectivity Score
  const connectivityPassed = Object.values(validationResults.connectivity)
    .filter(test => test.status === 'success' && test.accessible).length;
  const connectivityTotal = Object.keys(validationResults.connectivity).length;
  console.log(`\n🌐 Connectivity: ${connectivityPassed}/${connectivityTotal} tests passed`);

  // Security Score
  const securityScore = validationResults.security.headerScore || '0/4';
  const rateLimitingActive = validationResults.security.rateLimiting || false;
  console.log(`\n🛡️  Security:`);
  console.log(`   Headers: ${securityScore}`);
  console.log(`   Rate Limiting: ${rateLimitingActive ? 'Active' : 'Inactive'}`);
  console.log(`   CORS: ${validationResults.security.cors?.['Access-Control-Allow-Origin'] ? 'Configured' : 'Not configured'}`);

  // Authentication Score
  const authWorking = validationResults.authentication.adminLogin?.status === 'success';
  const protectedWorking = validationResults.authentication.protectedAccess?.status === 'success';
  console.log(`\n🔐 Authentication:`);
  console.log(`   Admin Login: ${authWorking ? 'Working' : 'Failed'}`);
  console.log(`   Protected Endpoints: ${protectedWorking ? 'Working' : 'Failed'}`);
  console.log(`   Invalid Login Rejection: ${validationResults.authentication.invalidLogin?.rejected ? 'Working' : 'Failed'}`);

  // Environment Score
  const runningContainers = validationResults.environment.containers?.filter(c => c.healthy).length || 0;
  const totalContainers = validationResults.environment.containers?.length || 0;
  console.log(`\n🌍 Environment:`);
  console.log(`   Docker Containers: ${runningContainers}/${totalContainers} running`);

  // Performance
  const avgResponseTime = validationResults.performance.healthEndpoint?.averageResponseTime || 0;
  console.log(`\n⚡ Performance:`);
  console.log(`   Average Response Time: ${avgResponseTime.toFixed(2)}ms`);

  // Overall Assessment
  console.log('\n🎯 PRODUCTION READINESS ASSESSMENT:');

  let readinessScore = 0;
  let maxScore = 0;

  // Connectivity (20 points)
  maxScore += 20;
  readinessScore += (connectivityPassed / connectivityTotal) * 20;

  // Security (30 points)
  maxScore += 30;
  const securityPoints = (parseInt(securityScore.split('/')[0]) / 4) * 15 +
                        (rateLimitingActive ? 10 : 0) +
                        (validationResults.security.cors?.['Access-Control-Allow-Origin'] ? 5 : 0);
  readinessScore += securityPoints;

  // Authentication (25 points)
  maxScore += 25;
  const authPoints = (authWorking ? 10 : 0) +
                    (protectedWorking ? 10 : 0) +
                    (validationResults.authentication.invalidLogin?.rejected ? 5 : 0);
  readinessScore += authPoints;

  // Environment (15 points)
  maxScore += 15;
  readinessScore += (runningContainers / totalContainers) * 15;

  // Performance (10 points)
  maxScore += 10;
  if (avgResponseTime < 50) readinessScore += 10;
  else if (avgResponseTime < 200) readinessScore += 7;
  else if (avgResponseTime < 500) readinessScore += 4;

  const readinessPercentage = (readinessScore / maxScore) * 100;

  console.log(`\n   Overall Score: ${readinessScore.toFixed(1)}/${maxScore} (${readinessPercentage.toFixed(1)}%)`);

  if (readinessPercentage >= 90) {
    console.log('   🟢 READY FOR PRODUCTION DEPLOYMENT');
  } else if (readinessPercentage >= 75) {
    console.log('   🟡 MOSTLY READY - Minor issues to address');
  } else if (readinessPercentage >= 60) {
    console.log('   🟠 NEEDS WORK - Several issues to fix');
  } else {
    console.log('   🔴 NOT READY - Major issues require attention');
  }

  // Recommendations
  console.log('\n💡 RECOMMENDATIONS:');

  if (!validationResults.security.rateLimiting) {
    console.log('   • Enable rate limiting for production security');
  }

  if (avgResponseTime > 200) {
    console.log('   • Optimize application performance - response times too high');
  }

  if (runningContainers < totalContainers) {
    console.log('   • Fix container startup issues before deployment');
  }

  if (!authWorking) {
    console.log('   • Critical: Fix authentication system before deployment');
  }

  const errorCount = validationResults.errors.length;
  if (errorCount > 0) {
    console.log(`   • Investigate and fix ${errorCount} test errors`);
  }

  console.log('\n🚀 COOLIFY DEPLOYMENT READINESS:');
  const coolifyReady = readinessPercentage >= 85 && authWorking && runningContainers === totalContainers;
  console.log(`   ${coolifyReady ? '✅ READY' : '❌ NOT READY'} for Coolify deployment`);

  if (coolifyReady) {
    console.log('\n   Next steps for Coolify:');
    console.log('   1. Update CORS_ORIGINS with production domain');
    console.log('   2. Set APP_ENV=production');
    console.log('   3. Configure SSL/TLS certificates');
    console.log('   4. Set up backup and monitoring');
  }

  console.log('\n' + '='.repeat(80));

  return {
    readinessScore: readinessPercentage,
    coolifyReady: coolifyReady,
    details: validationResults
  };
}

async function runValidation() {
  console.log('🚀 Starting LeafLock Deployment Validation\n');

  try {
    await testConnectivity();
    await testSecurity();
    await testAuthentication();
    await testEnvironment();
    await testPerformanceBasics();

    return await generateReport();

  } catch (error) {
    console.error('❌ Validation failed:', error.message);
    validationResults.errors.push({
      test: 'main',
      error: error.message
    });
    return validationResults;
  }
}

// Run the validation if this script is executed directly
if (require.main === module) {
  runValidation()
    .then((result) => {
      const exitCode = result.coolifyReady ? 0 : 1;
      process.exit(exitCode);
    })
    .catch((error) => {
      console.error('💥 Validation suite failed:', error);
      process.exit(1);
    });
}

module.exports = { runValidation, validationResults };