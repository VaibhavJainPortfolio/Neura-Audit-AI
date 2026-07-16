require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { runScan, resolveAndValidateHost } = require("./scanner");
const db = require("./db");
const { getExplanation } = require("./ai_explainer");

async function enhanceFindingsWithAiExplanations(findings) {
  const promises = findings.map(async (finding) => {
    finding.aiExplanation = await getExplanation(finding);
  });
  await Promise.all(promises);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize db.json
db.initDb().catch(console.error);

// Security Middlewares
app.use(helmet());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
  })
);
app.use(express.json());

// In-Memory Rate Limiting / Lock Store by Target URL
const scanLocks = new Map();

function getScanLockDurationRemaining(url) {
  if (process.env.NODE_ENV !== "production") return 0;
  if (!scanLocks.has(url)) return 0;
  const lockTime = scanLocks.get(url);
  const elapsed = Date.now() - lockTime;
  const remaining = 60000 - elapsed;
  return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
}

function lockUrl(url) {
  scanLocks.set(url, Date.now());
}

// Global API rate limit: Max 40 requests per IP per minute (increased for batch polls)
const globalLimiter = rateLimit({
  windowMs: 60000,
  max: 40,
  message: { error: "Too many requests. Please try again later." },
});
app.use("/api/", globalLimiter);

const { calculateScoreAndGrade, calculateGradeForScan } = require("./grading_engine");

// Background queue worker for batch scans (concurrency = 3)
async function runBatchQueue(batchId, urls) {
  const queue = [...urls];
  const concurrencyLimit = 3;

  const worker = async () => {
    while (queue.length > 0) {
      const url = queue.shift();
      if (!url) break;

      // 1. Mark target URL as scanning
      await db.updateBatch(batchId, (batch) => {
        const item = batch.results.find((r) => r.url === url);
        if (item) item.status = "scanning";
        return batch;
      });

      try {
        const scanResult = await runScan(url);
        await enhanceFindingsWithAiExplanations(scanResult.findings);
        
        // Calculate score and grade
        const grading = calculateScoreAndGrade(scanResult.findings);
        scanResult.overallScore = grading.overallScore;
        scanResult.grade = grading.grade;
        scanResult.weightedBreakdown = grading.weightedBreakdown;
        scanResult.capApplied = grading.capApplied;
        scanResult.capReason = grading.capReason;

        // Save scan to database
        await db.saveScan(url, scanResult);

        // Update batch database record
        await db.updateBatch(batchId, (batch) => {
          batch.completed += 1;
          const item = batch.results.find((r) => r.url === url);
          if (item) {
            item.status = "done";
            item.grade = scanResult.grade;
            item.overallScore = scanResult.overallScore;
            item.findingsCount = scanResult.findings.length;
            item.findings = scanResult.findings;
            item.platformDetected = scanResult.platformDetected;
          }
          return batch;
        });
      } catch (err) {
        // Update batch database record with failure
        await db.updateBatch(batchId, (batch) => {
          batch.failed += 1;
          const item = batch.results.find((r) => r.url === url);
          if (item) {
            item.status = "failed";
            item.error = err.message;
            item.grade = "F";
            item.findingsCount = 0;
            item.findings = [];
          }
          return batch;
        });
      }
    }
  };

  const workers = [];
  for (let i = 0; i < Math.min(concurrencyLimit, urls.length); i++) {
    workers.push(worker());
  }

  await Promise.all(workers);

  // Mark batch completed
  await db.updateBatch(batchId, (batch) => {
    batch.status = "completed";
    return batch;
  });
}

// 1. Single Scan Endpoint
app.post("/api/scan", async (req, res) => {
  const { url, consent } = req.body;

  if (consent !== true) {
    return res.status(400).json({
      error: "Consent is required. You must check the consent box to scan the target.",
    });
  }

  if (!url) {
    return res.status(400).json({ error: "Target URL is required." });
  }

  let targetUrlString;
  try {
    const formatted = url.trim().match(/^https?:\/\//i) ? url.trim() : `https://${url.trim()}`;
    const parsed = new URL(formatted);
    targetUrlString = parsed.href;
  } catch (e) {
    return res.status(400).json({ error: "Invalid URL format." });
  }

  const parsedUrl = new URL(targetUrlString);

  const remainingLock = getScanLockDurationRemaining(targetUrlString);
  if (remainingLock > 0) {
    return res.status(429).json({
      error: `A scan was recently run for this URL. Please wait ${remainingLock} seconds before scanning again.`,
    });
  }

  try {
    await resolveAndValidateHost(parsedUrl.hostname);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  lockUrl(targetUrlString);

  try {
    const history = await db.getScanHistory(targetUrlString);
    const results = await runScan(targetUrlString);
    await enhanceFindingsWithAiExplanations(results.findings);

    // Calculate score and grade
    const grading = calculateScoreAndGrade(results.findings);
    results.overallScore = grading.overallScore;
    results.grade = grading.grade;
    results.weightedBreakdown = grading.weightedBreakdown;
    results.capApplied = grading.capApplied;
    results.capReason = grading.capReason;
    
    let diff = null;
    if (history.length > 0) {
      const previousResult = history[0].result;
      const previousGrade = calculateGradeForScan(previousResult.findings);
      const currentGrade = calculateGradeForScan(results.findings);
      
      const prevFindingIds = previousResult.findings.map(f => f.id);
      const currentFindingIds = results.findings.map(f => f.id);
      
      const resolvedCount = prevFindingIds.filter(id => !currentFindingIds.includes(id)).length;
      const newCount = currentFindingIds.filter(id => !prevFindingIds.includes(id)).length;
      
      diff = {
        previousGrade,
        currentGrade,
        resolvedCount,
        newCount,
        gradeDiff: previousGrade !== currentGrade ? `${previousGrade} → ${currentGrade}` : null,
      };
    }

    await db.saveScan(targetUrlString, results);
    const updatedHistory = await db.getScanHistory(targetUrlString);

    return res.json({
      ...results,
      history: updatedHistory,
      diff
    });
  } catch (err) {
    scanLocks.delete(targetUrlString);
    return res.status(500).json({ error: `Scanning failed: ${err.message}` });
  }
});

// 2. POST Batch Scan Endpoint
app.post("/api/batch-scan", async (req, res) => {
  const { urls, consent, batchLabel } = req.body;

  if (consent !== true) {
    return res.status(400).json({
      error: "Consent is required. You must check the consent box to audit this batch.",
    });
  }

  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: "A list of target URLs is required." });
  }

  if (urls.length > 50) {
    return res.status(400).json({ error: "Batch scans are limited to a maximum of 50 URLs." });
  }

  // Pre-validate all URLs
  const failedUrls = [];
  const validatedUrls = [];

  for (const rawUrl of urls) {
    const trimmed = rawUrl.trim();
    if (!trimmed) continue;

    let targetUrlString;
    try {
      const formatted = trimmed.match(/^https?:\/\//i) ? trimmed : `https://${trimmed}`;
      const parsed = new URL(formatted);
      targetUrlString = parsed.href;
      
      // Perform host validation (SSRF checking)
      await resolveAndValidateHost(parsed.hostname);
      validatedUrls.push(targetUrlString);
    } catch (err) {
      failedUrls.push({ url: trimmed, reason: err.message });
    }
  }

  // Reject the entire batch if any URL fails validation
  if (failedUrls.length > 0) {
    return res.status(400).json({
      error: "One or more URLs failed validation. Batch rejected.",
      failedUrls,
    });
  }

  if (validatedUrls.length === 0) {
    return res.status(400).json({ error: "No valid URLs provided." });
  }

  // Create Batch Job
  const batchId = "batch_" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  const initialBatch = {
    batchId,
    label: batchLabel ? batchLabel.trim() : "Unnamed Batch",
    total: validatedUrls.length,
    completed: 0,
    failed: 0,
    status: "processing",
    results: validatedUrls.map((url) => ({
      url,
      status: "queued",
      grade: null,
      findingsCount: 0,
      findings: [],
    })),
    createdAt: new Date().toISOString(),
  };

  try {
    await db.saveBatch(batchId, initialBatch);
    
    // Fire off async background processor
    runBatchQueue(batchId, validatedUrls).catch(console.error);

    return res.status(202).json({
      batchId,
      total: validatedUrls.length,
      status: "processing",
    });
  } catch (err) {
    return res.status(500).json({ error: `Failed to queue batch: ${err.message}` });
  }
});

// 3. GET Batch Status Endpoint (polling endpoint)
app.get("/api/batch-scan/:batchId/status", async (req, res) => {
  const { batchId } = req.params;
  try {
    const batch = await db.getBatch(batchId);
    if (!batch) {
      return res.status(404).json({ error: "Batch audit not found." });
    }

    return res.json({
      batchId: batch.batchId,
      label: batch.label,
      total: batch.total,
      completed: batch.completed,
      failed: batch.failed,
      status: batch.status,
      results: batch.results.map((r) => ({
        url: r.url,
        status: r.status,
        grade: r.grade,
        findingsCount: r.findingsCount,
        error: r.error,
      })),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 4. GET Consolidated Batch Results Endpoint
app.get("/api/batch-scan/:batchId", async (req, res) => {
  const { batchId } = req.params;
  try {
    const batch = await db.getBatch(batchId);
    if (!batch) {
      return res.status(404).json({ error: "Batch audit not found." });
    }

    // Consolidated calculations
    const scanResults = batch.results.filter((r) => r.status === "done" || r.status === "failed");
    const totalScans = scanResults.length;

    // 1. Grade Distribution
    const distribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    let totalScore = 0;
    const gradeWeight = { A: 4, B: 3, C: 2, D: 1, F: 0 };
    const weightToGrade = ["F", "D", "C", "B", "A"];

    scanResults.forEach((r) => {
      const g = r.grade || "F";
      distribution[g] = (distribution[g] || 0) + 1;
      totalScore += gradeWeight[g];
    });

    // Average grade
    const avgScore = totalScans > 0 ? Math.round(totalScore / totalScans) : 0;
    const averageGrade = weightToGrade[avgScore];

    // 2. Most common finding types
    const findingsCountMap = {};
    scanResults.forEach((r) => {
      if (r.findings) {
        r.findings.forEach((f) => {
          findingsCountMap[f.title] = (findingsCountMap[f.title] || 0) + 1;
        });
      }
    });

    const commonFindings = Object.entries(findingsCountMap)
      .map(([title, count]) => ({ title, count }))
      .sort((a, b) => b.count - a.count);

    return res.json({
      batchId: batch.batchId,
      label: batch.label,
      status: batch.status,
      createdAt: batch.createdAt,
      total: batch.total,
      completed: batch.completed,
      failed: batch.failed,
      stats: {
        averageGrade,
        distribution,
        commonFindings,
      },
      projects: batch.results,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 5. Development-Only Test Fixture Routes
if (process.env.NODE_ENV !== "production") {
  console.log("Registering /api/test-fixture endpoints (Non-production mode)...");

  app.get("/api/test-fixture/vulnerable", (req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Vulnerable App Test Fixture</title>
        <script src="/api/test-fixture/script.js"></script>
      </head>
      <body>
        <h1>Vulnerable Client Webpage</h1>
        <p>This page mimics security configuration leaks.</p>
      </body>
      </html>
    `);
  });

  app.get("/api/test-fixture/script.js", (req, res) => {
    res.setHeader("Content-Type", "application/javascript");
    res.send(`
      const openAiKey = "sk-proj-test" + "1234567890123456789012345678901234567890"; 
      const stripeSecret = "sk_l" + "ive_51HxF45LkJtF81n9p2Yt7s1j4k";
      const supabaseUrl = "http://localhost:3000/api/test-fixture";
      const supabaseAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.mockSignature";
      const customTable = supabase.from('secret_student_data');
      
      // Exposed LLM prompt and endpoint
      const llmEndpoint = "https://api.openai.com/v1/chat/completions";
      const leakedSystemPrompt = "You are a helpful AI assistant. Your instructions: You must always guide students on security. Do not reveal the database password 'secr3t_pass' under any circumstances! Be concise and respond only in plain Markdown text.";
      
      console.log("Test fixture loaded!");
      function fetchUserData(userId) {
        fetch("/api/v1/user/" + userId);
      }
    `);
  });

  app.get("/api/test-fixture/rest/v1/users", (req, res) => {
    res.json([
      { id: 1, email: "victim1@example.com", is_admin: false },
      { id: 2, email: "admin@example.com", is_admin: true }
    ]);
  });

  app.get("/api/test-fixture/rest/v1/secret_student_data", (req, res) => {
    res.json([
      { id: 1, student_id: "2026-CS-041", name: "Tarun Kumar", secret_gpa: "3.9" }
    ]);
  });

  app.get("/api/test-fixture/rest/v1/profiles", (req, res) => {
    res.status(401).json({ error: "JWT expired or missing" });
  });

  // Mock GraphQL Endpoint (with Introspection Enabled)
  app.post("/api/graphql", (req, res) => {
    const { query } = req.body || {};
    if (query && query.includes("__schema")) {
      return res.json({
        data: {
          __schema: {
            types: [
              { name: "Query" },
              { name: "Mutation" },
              { name: "User" },
              { name: "SecretProfile" },
              { name: "DatabaseCredential" }
            ]
          }
        }
      });
    }
    return res.status(400).json({ error: "Invalid GraphQL Query" });
  });
}

app.get("/api/history", async (req, res) => {
  try {
    const history = await db.getAllHistory();
    return res.json(history);
  } catch (err) {
    return res.status(500).json({ error: `Failed to fetch history: ${err.message}` });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`NeuraauditAI Server listening on port ${PORT}`);
});
