const fs = require("fs").promises;
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const dbPath = path.join(__dirname, "db.json");

// Initialize Supabase Client if env variables are present
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_KEY) {
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
  console.log("=== Database Connection: Connected to Supabase ===");
} else {
  console.log("=== Database Connection: Using Local file db.json ===");
}

// Ensure the db.json file exists with initial schema (only when not using Supabase)
async function initDb() {
  if (supabase) return;
  try {
    await fs.access(dbPath);
  } catch (err) {
    const initialData = { scans: {}, batches: {} };
    await fs.writeFile(dbPath, JSON.stringify(initialData, null, 2), "utf8");
  }
}

// Read database helper (local fallback)
async function readDb() {
  try {
    const data = await fs.readFile(dbPath, "utf8");
    return JSON.parse(data);
  } catch (err) {
    return { scans: {}, batches: {} };
  }
}

// Transaction queue to serialize read-modify-write blocks (local fallback)
let transactionQueue = Promise.resolve();

async function runTransaction(updateFn) {
  return new Promise((resolve, reject) => {
    transactionQueue = transactionQueue.then(async () => {
      try {
        await initDb();
        const db = await readDb();
        const updatedDb = await updateFn(db);
        await fs.writeFile(dbPath, JSON.stringify(updatedDb, null, 2), "utf8");
        resolve(updatedDb);
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Public API methods
async function saveScan(url, result) {
  if (supabase) {
    try {
      const { error } = await supabase
        .from("scans")
        .insert({
          url,
          result,
          timestamp: new Date().toISOString()
        });
      if (error) throw error;
    } catch (err) {
      console.error("Supabase saveScan error:", err.message);
    }
  } else {
    await runTransaction(async (db) => {
      if (!db.scans[url] || !Array.isArray(db.scans[url])) {
        db.scans[url] = [];
      }
      db.scans[url].unshift({
        result,
        timestamp: new Date().toISOString(),
      });
      if (db.scans[url].length > 10) {
        db.scans[url] = db.scans[url].slice(0, 10);
      }
      return db;
    });
  }
}

async function getScan(url) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("scans")
        .select("result")
        .eq("url", url)
        .order("timestamp", { ascending: false })
        .limit(1);
      if (error) throw error;
      return data && data.length > 0 ? data[0].result : null;
    } catch (err) {
      console.error("Supabase getScan error:", err.message);
      return null;
    }
  } else {
    const db = await readDb();
    const history = db.scans[url];
    if (history && Array.isArray(history) && history.length > 0) {
      return history[0].result;
    }
    return null;
  }
}

async function getScanHistory(url) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("scans")
        .select("result, timestamp")
        .eq("url", url)
        .order("timestamp", { ascending: false })
        .limit(10);
      if (error) throw error;
      return (data || []).map(row => ({
        result: row.result,
        timestamp: row.timestamp
      }));
    } catch (err) {
      console.error("Supabase getScanHistory error:", err.message);
      return [];
    }
  } else {
    const db = await readDb();
    const history = db.scans[url];
    return Array.isArray(history) ? history : [];
  }
}

async function saveBatch(batchId, batchData) {
  if (supabase) {
    try {
      const { error } = await supabase
        .from("batches")
        .upsert({
          batch_id: batchId,
          batch_data: batchData,
          created_at: batchData.createdAt || new Date().toISOString()
        });
      if (error) throw error;
    } catch (err) {
      console.error("Supabase saveBatch error:", err.message);
    }
  } else {
    await runTransaction(async (db) => {
      db.batches[batchId] = batchData;
      return db;
    });
  }
}

async function getBatch(batchId) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("batches")
        .select("batch_data")
        .eq("batch_id", batchId)
        .maybeSingle();
      if (error) throw error;
      return data ? data.batch_data : null;
    } catch (err) {
      console.error("Supabase getBatch error:", err.message);
      return null;
    }
  } else {
    const db = await readDb();
    return db.batches[batchId] || null;
  }
}

async function updateBatch(batchId, updateFn) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("batches")
        .select("batch_data")
        .eq("batch_id", batchId)
        .maybeSingle();
      if (error) throw error;
      if (data) {
        const updatedData = updateFn(data.batch_data);
        const { error: updateErr } = await supabase
          .from("batches")
          .update({ batch_data: updatedData })
          .eq("batch_id", batchId);
        if (updateErr) throw updateErr;
      }
    } catch (err) {
      console.error("Supabase updateBatch error:", err.message);
    }
  } else {
    await runTransaction(async (db) => {
      if (db.batches[batchId]) {
        db.batches[batchId] = updateFn(db.batches[batchId]);
      }
      return db;
    });
  }
}

async function cleanupOldRecords() {
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  if (supabase) {
    try {
      const dateStr = new Date(thirtyDaysAgo).toISOString();
      await supabase.from("scans").delete().lt("timestamp", dateStr);
      await supabase.from("batches").delete().lt("created_at", dateStr);
    } catch (err) {
      console.error("Supabase cleanupOldRecords error:", err.message);
    }
  } else {
    await runTransaction(async (db) => {
      // Clean up single scans
      if (db.scans) {
        for (const [url, history] of Object.entries(db.scans)) {
          if (Array.isArray(history)) {
            db.scans[url] = history.filter((scan) => {
              return scan.timestamp && new Date(scan.timestamp).getTime() >= thirtyDaysAgo;
            });
            if (db.scans[url].length === 0) {
              delete db.scans[url];
            }
          } else {
            delete db.scans[url];
          }
        }
      }
      // Clean up batches
      if (db.batches) {
        for (const [batchId, batch] of Object.entries(db.batches)) {
          if (batch.createdAt && new Date(batch.createdAt).getTime() < thirtyDaysAgo) {
            delete db.batches[batchId];
          }
        }
      }
      return db;
    });
  }
}

async function getAiExplanation(key) {
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("ai_cache")
        .select("value")
        .eq("key", key)
        .maybeSingle();
      if (error) throw error;
      return data ? data.value : null;
    } catch (err) {
      console.error("Supabase getAiExplanation error:", err.message);
      return null;
    }
  } else {
    const db = await readDb();
    return db.aiCache ? db.aiCache[key] : null;
  }
}

async function saveAiExplanation(key, value) {
  if (supabase) {
    try {
      const { error } = await supabase
        .from("ai_cache")
        .upsert({ key, value });
      if (error) throw error;
    } catch (err) {
      console.error("Supabase saveAiExplanation error:", err.message);
    }
  } else {
    await runTransaction(async (db) => {
      if (!db.aiCache) {
        db.aiCache = {};
      }
      db.aiCache[key] = value;
      return db;
    });
  }
}

async function getAllHistory() {
  if (supabase) {
    try {
      // 1. Fetch scans
      const { data: rawScans, error: scansErr } = await supabase
        .from("scans")
        .select("url, result, timestamp")
        .order("timestamp", { ascending: false });
      if (scansErr) throw scansErr;

      // Group and consolidate unique URLs
      const scansMap = {};
      (rawScans || []).forEach(row => {
        if (!scansMap[row.url]) {
          scansMap[row.url] = {
            url: row.url,
            latestResult: row.result,
            timestamp: row.timestamp,
            historyCount: 1
          };
        } else {
          scansMap[row.url].historyCount++;
        }
      });
      const scansList = Object.values(scansMap);
      scansList.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // 2. Fetch batches
      const { data: rawBatches, error: batchesErr } = await supabase
        .from("batches")
        .select("batch_data, created_at")
        .order("created_at", { ascending: false });
      if (batchesErr) throw batchesErr;
      const batchesList = (rawBatches || []).map(row => row.batch_data);

      return {
        scans: scansList,
        batches: batchesList
      };
    } catch (err) {
      console.error("Supabase getAllHistory error:", err.message);
      return { scans: [], batches: [] };
    }
  } else {
    const db = await readDb();
    
    // Format scans history list (retrieve latest run for each url)
    const scansList = [];
    if (db.scans) {
      for (const [url, history] of Object.entries(db.scans)) {
        if (Array.isArray(history) && history.length > 0) {
          scansList.push({
            url,
            latestResult: history[0].result,
            timestamp: history[0].timestamp,
            historyCount: history.length
          });
        }
      }
    }

    // Format batches history list
    const batchesList = [];
    if (db.batches) {
      for (const [batchId, batch] of Object.entries(db.batches)) {
        batchesList.push(batch);
      }
    }

    // Sort lists (newest first)
    scansList.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    batchesList.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return {
      scans: scansList,
      batches: batchesList
    };
  }
}

module.exports = {
  initDb,
  saveScan,
  getScan,
  getScanHistory,
  saveBatch,
  getBatch,
  updateBatch,
  cleanupOldRecords,
  getAiExplanation,
  saveAiExplanation,
  getAllHistory,
};
