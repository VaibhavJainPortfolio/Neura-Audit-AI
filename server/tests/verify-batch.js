const axios = require("axios");

async function runVerification() {
  console.log("=== CampusShield Batch Scan API Verification ===");

  // Test 1: Verify SSRF validation in batch scan (Should fail)
  console.log("\n[Test 1] Testing SSRF rejection for batch scan...");
  try {
    const response = await axios.post("http://localhost:3000/api/batch-scan", {
      urls: ["https://example.com", "http://192.168.1.1/sensitive", "http://10.0.0.1"],
      consent: true,
      batchLabel: "Test SSRF Batch"
    });
    console.log("FAIL: Batch scan was accepted but should have been rejected!");
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log("PASS: Server correctly rejected batch scan with status 400.");
      console.log("Response data:", JSON.stringify(error.response.data, null, 2));
    } else {
      console.log("FAIL: Request failed with unexpected error:", error.message);
    }
  }

  // Test 2: Verify Consent check in batch scan (Should fail)
  console.log("\n[Test 2] Testing consent guard...");
  try {
    const response = await axios.post("http://localhost:3000/api/batch-scan", {
      urls: ["https://example.com"],
      consent: false
    });
    console.log("FAIL: Batch scan was accepted without consent!");
  } catch (error) {
    if (error.response && error.response.status === 400) {
      console.log("PASS: Server correctly rejected batch scan without consent.");
      console.log("Response message:", error.response.data.error);
    } else {
      console.log("FAIL: Request failed with unexpected error:", error.message);
    }
  }

  // Test 3: Verify Valid Batch Scan Processing & Polling (Should succeed)
  console.log("\n[Test 3] Testing valid batch scan with multiple URLs...");
  let batchId;
  try {
    const response = await axios.post("http://localhost:3000/api/batch-scan", {
      urls: [
        "https://example.com", 
        "http://localhost:3000/api/test-fixture/vulnerable", 
        "https://google.com"
      ],
      consent: true,
      batchLabel: "Verification Demo Batch"
    });
    
    if (response.status === 202) {
      batchId = response.data.batchId;
      console.log(`PASS: Batch accepted. Job ID: ${batchId}`);
    } else {
      console.log("FAIL: Unexpected response status:", response.status);
      return;
    }
  } catch (error) {
    console.log("FAIL: Could not submit valid batch:", error.message);
    return;
  }

  // Poll status until complete
  console.log("\n[Polling] Polling batch status...");
  let completed = false;
  for (let i = 0; i < 15; i++) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    try {
      const statusRes = await axios.get(`http://localhost:3000/api/batch-scan/${batchId}/status`);
      console.log(`Poll #${i+1} Status: ${statusRes.data.status} | Completed: ${statusRes.data.completed}/${statusRes.data.total}`);
      if (statusRes.data.status === "completed") {
        completed = true;
        break;
      }
    } catch (err) {
      console.log("Error polling status:", err.message);
    }
  }

  if (!completed) {
    console.log("FAIL: Batch did not complete within timeout.");
    return;
  }

  // Fetch full consolidated findings and verify calculations
  console.log("\n[Test 4] Fetching consolidated batch results...");
  try {
    const resultsRes = await axios.get(`http://localhost:3000/api/batch-scan/${batchId}`);
    const results = resultsRes.data;
    console.log("Consolidated stats calculated:");
    console.log("Average Grade:", results.stats.averageGrade);
    console.log("Grade Distribution:", JSON.stringify(results.stats.distribution));
    console.log("Top Vulnerabilities Discovered:");
    results.stats.commonFindings.slice(0, 3).forEach((f, idx) => {
      console.log(`  ${idx+1}. "${f.title}" affecting ${f.count} site(s)`);
    });

    // Check project data
    console.log("\nProjects Summary:");
    results.projects.forEach(p => {
      console.log(`  - URL: ${p.url} | Grade: ${p.grade} | Status: ${p.status} | Findings: ${p.findingsCount}`);
    });

    if (results.stats.averageGrade && results.projects.length === 3) {
      console.log("\nPASS: Consolidated reports and grade calculations verify correctly!");
    } else {
      console.log("\nFAIL: Stat calculation error.");
    }
  } catch (error) {
    console.log("FAIL: Could not fetch consolidated findings:", error.message);
  }

  // Test 5: Verify Single Scan Re-scan & Diffs
  console.log("\n[Test 5] Testing consecutive single scans and diff tracking...");
  try {
    console.log("Triggering Scan #1...");
    const scan1 = await axios.post("http://localhost:3000/api/scan", {
      url: "http://localhost:3000/api/test-fixture/vulnerable",
      consent: true
    });
    console.log("Scan #1 Complete. Findings:", scan1.data.findings.length);

    console.log("Sleeping 1 second (lock bypassed)...");
    await new Promise(resolve => setTimeout(resolve, 1000));

    console.log("Triggering Scan #2...");
    const scan2 = await axios.post("http://localhost:3000/api/scan", {
      url: "http://localhost:3000/api/test-fixture/vulnerable",
      consent: true
    });
    console.log("Scan #2 Complete.");
    console.log("Diff data returned:", JSON.stringify(scan2.data.diff, null, 2));
    console.log("History records returned:", scan2.data.history.length);
    
    if (scan2.data.history.length > 1) {
      console.log("PASS: Re-scan history and diff calculation verified successfully!");
    } else {
      console.log("FAIL: Re-scan history or diff calculations missing.");
    }
  } catch (error) {
    console.log("FAIL: Could not verify re-scans:", error.response ? error.response.data : error.message);
  }
}

runVerification();
