
const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const { performance } = require('perf_hooks');

// Configuration
const API_ENDPOINT = 'http://localhost:3000/api/request-access';
const ITERATIONS = 100;
const CONCURRENCY = [1, 5, 10, 20, 50, 100];
const RESOURCE_PREFIX = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
const REQUESTER = '0xRequesterAddress';

// Results storage
const results = {
  tps: {},
  latency: {},
  gasUsage: {}
};

async function runBenchmark(concurrentRequests) {
  console.log(`Running benchmark with ${concurrentRequests} concurrent requests`);
  
  // Create requests
  const requests = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const resourceId = RESOURCE_PREFIX + i.toString(16).padStart(2, '0');
    const validUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    
    requests.push({
      resourceId,
      requester: REQUESTER,
      validUntil,
      cloudProvider: 'aws',
      policyArn: 'arn:aws:iam::123456789012:policy/TestPolicy',
      username: 'benchmarkuser'
    });
  }
  
  // Measure start time
  const startTime = performance.now();
  
  // Send requests in batches according to concurrency
  const batchSize = concurrentRequests;
  const batches = Math.ceil(requests.length / batchSize);
  const responses = [];
  
  for (let i = 0; i < batches; i++) {
    const batch = requests.slice(i * batchSize, (i + 1) * batchSize);
    const batchPromises = batch.map(req => {
      const start = performance.now();
      return axios.post(API_ENDPOINT, req)
        .then(res => {
          const latency = performance.now() - start;
          return { success: true, latency, gas: res.data.gasUsed };
        })
        .catch(err => {
          const latency = performance.now() - start;
          return { success: false, latency, error: err.message };
        });
    });
    
    const batchResponses = await Promise.all(batchPromises);
    responses.push(...batchResponses);
  }
  
  // Measure end time
  const endTime = performance.now();
  const totalTime = endTime - startTime;
  
  // Calculate results
  const successfulRequests = responses.filter(r => r.success).length;
  const tps = (successfulRequests / totalTime) * 1000;
  
  const latencies = responses.map(r => r.latency);
  const avgLatency = latencies.reduce((sum, lat) => sum + lat, 0) / latencies.length;
  
  const gasUsage = responses.filter(r => r.success && r.gas)
    .map(r => parseInt(r.gas));
  const avgGasUsage = gasUsage.length > 0 
    ? gasUsage.reduce((sum, gas) => sum + gas, 0) / gasUsage.length
    : 0;
  
  // Store results
  results.tps[concurrentRequests] = tps;
  results.latency[concurrentRequests] = avgLatency;
  results.gasUsage[concurrentRequests] = avgGasUsage;
  
  console.log(`Concurrency: ${concurrentRequests}`);
  console.log(`Successful requests: ${successfulRequests}/${ITERATIONS}`);
  console.log(`TPS: ${tps.toFixed(2)}`);
  console.log(`Average latency: ${avgLatency.toFixed(2)}ms`);
  console.log(`Average gas usage: ${avgGasUsage}`);
  console.log('---------------------------');
}

async function main() {
  for (const concurrency of CONCURRENCY) {
    await runBenchmark(concurrency);
  }
  
  // Save results to file
  fs.writeFileSync('benchmark-results.json', JSON.stringify(results, null, 2));
  console.log('Benchmark complete! Results saved to benchmark-results.json');
}

main().catch(console.error);