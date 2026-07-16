import React, { useState, useEffect, useMemo } from "react";
import { 
  Shield, 
  ShieldAlert,
  Lock, 
  Unlock, 
  AlertTriangle, 
  CheckCircle, 
  HelpCircle, 
  ArrowRight, 
  Copy, 
  Check, 
  RefreshCw, 
  Download, 
  Mail, 
  ExternalLink,
  Globe,
  Database,
  Grid,
  FileCode,
  AlertOctagon,
  FileText,
  Upload,
  ChevronDown,
  ChevronUp,
  ArrowUpDown,
  BookOpen,
  Server,
  Key,
  Brain,
  Clock
} from "lucide-react";
import confetti from "canvas-confetti";
import Papa from "papaparse";

const API_BASE = import.meta.env.VITE_API_URL || "";

// Compute grade letter from findings list
const getGradeForFindings = (findings) => {
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;
  const lowCount = findings.filter(f => f.severity === "low").length;

  if (criticalCount > 0) return "F";
  if (highCount > 0) return "D";
  if (mediumCount > 0) return "C";
  if (lowCount > 0) return "B";
  return "A";
};

export default function App() {
  const [viewMode, setViewMode] = useState("single"); // single | batch
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState("landing"); // landing | scanning | results | error | batch-scanning | batch-results
  const [errorMessage, setErrorMessage] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const [activeHistoryIndex, setActiveHistoryIndex] = useState(null);
  const [whyGradeExpanded, setWhyGradeExpanded] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);

  // Reset history index when scanning starts
  useEffect(() => {
    if (scanState === "scanning") {
      setActiveHistoryIndex(null);
    }
  }, [scanState]);

  const displayedResults = useMemo(() => {
    if (!scanResults) return null;
    if (activeHistoryIndex === null) return scanResults;
    if (scanResults.history && scanResults.history[activeHistoryIndex]) {
      return scanResults.history[activeHistoryIndex].result;
    }
    return scanResults;
  }, [scanResults, activeHistoryIndex]);
  
  // Progress tracking states
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [stepStatuses, setStepStatuses] = useState([]);
  
  // Clipboard copy state for findings
  const [copiedId, setCopiedId] = useState(null);
  
  // Email capture state
  const [email, setEmail] = useState("");
  const [emailSent, setEmailSent] = useState(false);

  // --- BATCH SCAN SPECIFIC STATES ---
  const [batchLabel, setBatchLabel] = useState("");
  const [urlTextarea, setUrlTextarea] = useState("");
  const [batchId, setBatchId] = useState(null);
  const [batchProgress, setBatchProgress] = useState(null);
  const [batchResults, setBatchResults] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: "url", direction: "asc" });
  const [expandedProjectUrl, setExpandedProjectUrl] = useState(null);
  const [batchValidationErrors, setBatchValidationErrors] = useState([]);

  // --- GLOBAL SCAN HISTORY ---
  const [historyData, setHistoryData] = useState({ scans: [], batches: [] });
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const response = await fetch(`${API_BASE}/api/history`);
      if (response.ok) {
        const data = await response.json();
        setHistoryData(data);
      }
    } catch (err) {
      console.error("Failed to fetch history:", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleLoadPastScan = (result) => {
    setScanResults(result);
    setScanState("results");
    setUrl(result.url);
    setConsent(true);
  };

  const handleLoadPastBatch = async (id) => {
    setErrorMessage("");
    setScanState("batch-scanning");
    setBatchProgress(null);
    setBatchId(id);
    try {
      const resultsRes = await fetch(`${API_BASE}/api/batch-scan/${id}`);
      if (resultsRes.ok) {
        const resultsData = await resultsRes.json();
        setBatchResults(resultsData);
        setScanState("batch-results");
      } else {
        setErrorMessage("Failed to load past batch findings.");
        setScanState("error");
      }
    } catch (err) {
      setErrorMessage("Failed to connect to batch scan endpoint.");
      setScanState("error");
    }
  };

  useEffect(() => {
    if (scanState === "landing") {
      fetchHistory();
    }
  }, [scanState]);

  const scanSteps = useMemo(() => [
    { name: "SSRF & Host Resolution Validation", key: "ssrf" },
    { name: "Checking SSL/TLS and HTTPS Redirects", key: "ssl" },
    { name: "Checking Exposed Static Files (.env, .git)", key: "files" },
    { name: "Auditing Security Headers & Cookie Flags", key: "headers" },
    { name: "Scanning Script Bundles for API Keys & Secrets", key: "secrets" },
    { name: "Testing Database Configurations & RLS Settings", key: "database" },
    { name: "Analyzing Library Versions & URL Patterns", key: "libraries" }
  ], []);

  // Parse multi-line URLs text box in real time
  const parsedUrls = useMemo(() => {
    return urlTextarea
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }, [urlTextarea]);

  // Live syntax checks for batch URLs before submission
  const urlChecklist = useMemo(() => {
    return parsedUrls.map((urlStr) => {
      // simple format checks
      let isValid = true;
      let reason = "";

      if (urlStr.includes("localhost") || urlStr.includes("127.0.0.1") || urlStr.includes("169.254")) {
        isValid = false;
        reason = "Private / Local address blocked.";
      } else {
        const hasDot = urlStr.includes(".");
        if (!hasDot) {
          isValid = false;
          reason = "Missing domain extension (e.g. .com).";
        }
      }
      return { url: urlStr, isValid, reason };
    });
  }, [parsedUrls]);

  // Determine if batch audit button should be disabled
  const isBatchSubmitDisabled = useMemo(() => {
    if (parsedUrls.length === 0) return true;
    if (parsedUrls.length > 50) return true;
    if (!consent) return true;
    // Disable if there are any syntactically invalid URLs
    return urlChecklist.some((item) => !item.isValid);
  }, [parsedUrls, consent, urlChecklist]);

  // Handle CSV file uploads and extract URLs
  const handleCsvUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    Papa.parse(file, {
      skipEmptyLines: true,
      header: false,
      complete: (results) => {
        const foundUrls = [];
        results.data.forEach((row) => {
          // Look for any cell that resembles a domain or URL
          const rowValues = Object.values(row).map((val) => String(val).trim());
          const cellUrl = rowValues.find((val) => {
            return (val.includes(".") && val.length > 3) || val.startsWith("http");
          });
          if (cellUrl) {
            foundUrls.push(cellUrl);
          }
        });

        if (foundUrls.length > 0) {
          setUrlTextarea(foundUrls.join("\n"));
        } else {
          alert("Could not find any columns containing URLs in this CSV file.");
        }
      },
      error: () => {
        alert("Failed to parse CSV file. Ensure it is formatted correctly.");
      }
    });
  };

  // Initialize step statuses on scanning start
  useEffect(() => {
    if (scanState === "scanning") {
      setStepStatuses(scanSteps.map(step => ({ ...step, status: "pending" })));
      setCurrentStepIndex(0);
    }
  }, [scanState, scanSteps]);

  // SINGLE SCAN: Execute scan request and progress animation
  useEffect(() => {
    if (scanState !== "scanning") return;

    let active = true;

    const triggerScan = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/scan`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url, consent })
        });

        const data = await response.json();

        if (!response.ok) {
          if (active) {
            setErrorMessage(data.error || "Scanning failed unexpectedly.");
            setScanState("error");
          }
          return;
        }

        // Simulate step transitions for realistic feel
        let step = 0;
        const interval = setInterval(() => {
          if (!active) {
            clearInterval(interval);
            return;
          }

          setStepStatuses(prev => {
            const next = [...prev];
            if (step < next.length) {
              next[step].status = "running";
              if (step > 0) {
                const prevStep = next[step - 1];
                const hasFailures = checkStepHasFailures(prevStep.key, data.findings);
                next[step - 1].status = hasFailures ? "fail" : "pass";
              }
              setCurrentStepIndex(step);
            } else {
              clearInterval(interval);
              const lastStep = next[next.length - 1];
              const hasFailures = checkStepHasFailures(lastStep.key, data.findings);
              next[next.length - 1].status = hasFailures ? "fail" : "pass";
              
              setTimeout(() => {
                if (active) {
                  setScanResults(data);
                  setScanState("results");
                  triggerConfetti(data.findings);
                }
              }, 600);
            }
            return next;
          });
          step++;
        }, 500);

      } catch (err) {
        if (active) {
          setErrorMessage("Failed to communicate with scanning server.");
          setScanState("error");
        }
      }
    };

    triggerScan();

    return () => {
      active = false;
    };
  }, [scanState, url, consent]);

  // BATCH SCAN: Start job and poll for status
  const startBatchScan = async () => {
    setBatchValidationErrors([]);
    setErrorMessage("");
    setScanState("batch-scanning");
    setBatchProgress(null);

    try {
      const response = await fetch(`${API_BASE}/api/batch-scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          urls: parsedUrls,
          consent,
          batchLabel: batchLabel || undefined
        })
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 400 && data.failedUrls) {
          // Pre-validation SSRF error
          setBatchValidationErrors(data.failedUrls);
          setErrorMessage(data.error);
        } else {
          setErrorMessage(data.error || "Failed to initialize batch scan job.");
        }
        setScanState("error");
        return;
      }

      setBatchId(data.batchId);
    } catch (err) {
      setErrorMessage("Failed to connect to batch scan endpoint.");
      setScanState("error");
    }
  };

  // Poll for batch scan progress
  useEffect(() => {
    if (scanState !== "batch-scanning" || !batchId) return;

    let active = true;
    let pollInterval;

    const pollStatus = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/batch-scan/${batchId}/status`);
        if (!response.ok) return;

        const data = await response.json();
        if (!active) return;

        setBatchProgress(data);

        if (data.status === "completed") {
          clearInterval(pollInterval);
          // Load full consolidated results
          const resultsRes = await fetch(`${API_BASE}/api/batch-scan/${batchId}`);
          if (resultsRes.ok) {
            const resultsData = await resultsRes.json();
            if (active) {
              setBatchResults(resultsData);
              setScanState("batch-results");
              confetti({
                particleCount: 150,
                spread: 80,
                origin: { y: 0.6 },
                colors: ["#66fcf1", "#10b981", "#ffffff"]
              });
            }
          } else {
            if (active) {
              setErrorMessage("Failed to load consolidated batch findings.");
              setScanState("error");
            }
          }
        }
      } catch (err) {
        console.error("Status polling error:", err);
      }
    };

    pollStatus();
    pollInterval = setInterval(pollStatus, 2000);

    return () => {
      active = false;
      clearInterval(pollInterval);
    };
  }, [scanState, batchId]);

  // Helper to determine if a check category has findings
  const checkStepHasFailures = (key, findings) => {
    if (!findings) return false;
    switch (key) {
      case "ssrf":
        return false;
      case "ssl":
        return findings.some(f => f.id.startsWith("ssl") || f.id === "http-no-redirect");
      case "files":
        return findings.some(f => f.id.startsWith("exposed-file"));
      case "headers":
        return findings.some(f => f.id.startsWith("header-missing") || f.id.startsWith("cookie") || f.id.startsWith("auth-cache"));
      case "secrets":
        return findings.some(f => f.id.startsWith("key-") || f.id === "exposed-supabase-service-role");
      case "database":
        return findings.some(f => f.id.startsWith("supabase-rls") || f.id === "firebase-firestore-rls-bypass");
      case "libraries":
        return findings.some(f => f.id === "vulnerable-jquery" || f.id === "idor-url-smell" || f.id === "exposed-source-map");
      default:
        return false;
    }
  };

  const triggerConfetti = (findings) => {
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    if (criticalCount === 0 && highCount === 0) {
      confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 },
        colors: ["#66fcf1", "#10b981", "#ffffff"]
      });
    }
  };

  // Grade computation (Single Scan)
  const gradeInfo = useMemo(() => {
    if (!displayedResults) return { grade: "F", color: "text-cyber-red", border: "border-cyber-red", bg: "bg-cyber-red/10", label: "Critical Risk" };
    
    if (displayedResults.grade !== undefined) {
      const g = displayedResults.grade;
      const severityLabels = {
        A: { label: "Excellent Posture", color: "text-[#10b981]", border: "border-[#10b981]/40", bg: "bg-[#10b981]/10" },
        B: { label: "Minor Issues", color: "text-[#66fcf1]", border: "border-[#66fcf1]/40", bg: "bg-[#66fcf1]/5" },
        C: { label: "Medium Risk Issues", color: "text-[#f59e0b]", border: "border-[#f59e0b]/40", bg: "bg-[#f59e0b]/5" },
        D: { label: "High Risk Issues", color: "text-[#ef4444]", border: "border-[#ef4444]/40", bg: "bg-[#ef4444]/10" },
        F: { label: "Critical Vulnerabilities", color: "text-[#ef4444]", border: "border-[#ef4444]/40", bg: "bg-[#ef4444]/10" }
      };
      const style = severityLabels[g] || severityLabels.F;
      return {
        grade: g,
        ...style
      };
    }

    const findings = displayedResults.findings;
    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount = findings.filter(f => f.severity === "high").length;
    const mediumCount = findings.filter(f => f.severity === "medium").length;
    const lowCount = findings.filter(f => f.severity === "low").length;

    if (criticalCount > 0) {
      return { grade: "F", color: "text-[#ef4444]", border: "border-[#ef4444]/40", bg: "bg-[#ef4444]/10", label: "Critical Vulnerabilities" };
    }
    if (highCount > 0) {
      return { grade: "D", color: "text-[#f59e0b]", border: "border-[#f59e0b]/40", bg: "bg-[#f59e0b]/10", label: "High Risk Issues" };
    }
    if (mediumCount > 0) {
      return { grade: "C", color: "text-[#f59e0b]", border: "border-[#f59e0b]/40", bg: "bg-[#f59e0b]/5", label: "Medium Risk Issues" };
    }
    if (lowCount > 0) {
      return { grade: "B", color: "text-[#66fcf1]", border: "border-[#66fcf1]/40", bg: "bg-[#66fcf1]/5", label: "Minor Issues" };
    }
    return { grade: "A", color: "text-[#10b981]", border: "border-[#10b981]/40", bg: "bg-[#10b981]/10", label: "Excellent Posture" };
  }, [displayedResults]);

  // Scores by category out of 100 (Single Scan)
  const categoryScores = useMemo(() => {
    if (!displayedResults) return [];

    if (displayedResults.weightedBreakdown) {
      return displayedResults.weightedBreakdown.map(item => ({
        name: item.category,
        score: item.score,
        weight: item.weight,
        contribution: item.contributionToOverall
      }));
    }

    const findings = displayedResults.findings;
    const categories = [
      { name: "Secrets", key: "Secrets" },
      { name: "Database", key: "Database" },
      { name: "Network", key: "Network" },
      { name: "AI/LLM Exposure", key: "AI_LLM" },
      { name: "App Layer", key: "Application" },
      { name: "Dependencies", key: "Dependencies" }
    ];

    return categories.map(cat => {
      let deductions = 0;
      findings.forEach(f => {
        if (f.category === cat.key) {
          if (f.severity === "critical") deductions += 40;
          else if (f.severity === "high") deductions += 25;
          else if (f.severity === "medium") deductions += 15;
          else if (f.severity === "low") deductions += 5;
        }
      });
      return {
        name: cat.name,
        score: Math.max(0, 100 - deductions)
      };
    });
  }, [displayedResults]);

  // Sortable batch projects list
  const sortedBatchProjects = useMemo(() => {
    if (!batchResults || !batchResults.projects) return [];
    const projects = [...batchResults.projects];

    projects.sort((a, b) => {
      let aVal = a[sortConfig.key];
      let bVal = b[sortConfig.key];

      if (sortConfig.key === "grade") {
        const weights = { A: 5, B: 4, C: 3, D: 2, F: 1, null: 0 };
        aVal = weights[a.grade] || 0;
        bVal = weights[b.grade] || 0;
      }

      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;

      if (aVal < bVal) return sortConfig.direction === "asc" ? -1 : 1;
      if (aVal > bVal) return sortConfig.direction === "asc" ? 1 : -1;
      return 0;
    });

    return projects;
  }, [batchResults, sortConfig]);

  const handleSort = (key) => {
    let direction = "asc";
    if (sortConfig.key === key && sortConfig.direction === "asc") {
      direction = "desc";
    }
    setSortConfig({ key, direction });
  };

  const handleCopyPrompt = (id, text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleEmailReport = (e) => {
    e.preventDefault();
    if (!email) return;
    setEmailSent(true);
    setTimeout(() => setEmailSent(false), 4000);
  };

  const handlePrint = () => {
    window.print();
  };

  // CSV Exporter for Batch Summary
  const exportBatchCsv = () => {
    if (!batchResults) return;

    const headers = ["Target URL", "Audit Grade", "Vulnerability Count", "Primary Platform", "Status", "Errors"];
    const rows = batchResults.projects.map((p) => [
      p.url,
      p.grade || "N/A",
      p.findingsCount || 0,
      p.platformDetected || "Generic/Other",
      p.status,
      p.error || ""
    ]);

    const csvContent = [
      headers.join(","),
      ...rows.map((row) => row.map((val) => `"${String(val).replace(/"/g, '""')}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const urlStr = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", urlStr);
    link.setAttribute("download", `neuraauditai_batch_${batchResults.batchId}_summary.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      {/* Cybernetic grid scanner background */}
      <div className="cyber-grid-container">
        <div className="cyber-grid" />
        <div className="cyber-scanner" />
        <div className="cyber-glow-orb" />
      </div>

      {/* Header */}
      <header className="border-b border-[#1f2833]/60 bg-[#0b0c10]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => {
            setScanResults(null);
            setBatchResults(null);
            setScanState("landing");
          }}>
            <div className="h-9 w-9 rounded-lg bg-cyber-light/10 border border-cyber-light/30 flex items-center justify-center glow-teal">
              <Shield className="h-5 w-5 text-cyber-light" />
            </div>
            <div>
              <span className="font-mono text-sm sm:text-lg font-bold tracking-tight text-white">Neura<span className="text-cyber-light">auditAI</span></span>
              <span className="hidden sm:inline-block ml-2 text-[9px] uppercase tracking-widest bg-cyber-light/10 text-cyber-light px-1.5 py-0.5 rounded border border-cyber-light/20">Audit Engine</span>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            {scanState !== "scanning" && scanState !== "batch-scanning" && (
              <div className="bg-[#1f2833]/30 border border-[#1f2833] rounded-lg p-1 flex">
                <button
                  onClick={() => {
                    setViewMode("single");
                    setScanState("landing");
                  }}
                  className={`text-[10px] sm:text-xs font-mono px-2 py-1.5 sm:px-3 sm:py-1.5 rounded transition-all cursor-pointer ${
                    scanState === "landing" && viewMode === "single" ? "bg-cyber-light text-cyber-dark font-bold" : "text-cyber-gray hover:text-white"
                  }`}
                >
                  Single Scan
                </button>
                <button
                  onClick={() => {
                    setViewMode("batch");
                    setScanState("landing");
                  }}
                  className={`text-[10px] sm:text-xs font-mono px-2 py-1.5 sm:px-3 sm:py-1.5 rounded transition-all cursor-pointer ${
                    scanState === "landing" && viewMode === "batch" ? "bg-cyber-light text-cyber-dark font-bold" : "text-cyber-gray hover:text-white"
                  }`}
                >
                  Batch Audit
                </button>
                <button
                  onClick={() => {
                    setViewMode("methodology");
                    setScanState("landing");
                  }}
                  className={`text-[10px] sm:text-xs font-mono px-2 py-1.5 sm:px-3 sm:py-1.5 rounded transition-all cursor-pointer ${
                    scanState === "landing" && viewMode === "methodology" ? "bg-cyber-light text-cyber-dark font-bold" : "text-cyber-gray hover:text-white"
                  }`}
                >
                  How We Scan
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-grow flex flex-col items-center">
        
        {/* Landing Screen */}
        {scanState === "landing" && (
          <div className="w-full max-w-4xl px-4 py-12 md:py-20 flex flex-col items-center">
            
            {/* Title / Hero */}
            <div className="text-center mb-10 max-w-2xl">
              <span className="font-mono text-xs text-cyber-light uppercase tracking-widest bg-cyber-light/5 border border-cyber-light/20 px-3 py-1 rounded-full">
                For Student Builders & Hackathons
              </span>
              <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight text-white mt-4 leading-tight">
                Verify Your Project's Security <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-light to-cyber-teal">
                  Before Demo Day
                </span>
              </h1>
              <p className="mt-4 text-sm md:text-base text-cyber-gray/80 leading-relaxed">
                {viewMode === "single" 
                  ? "Passive, read-only audit of your deployed app. Catch exposed keys, missing Supabase RLS, CORS mistakes, and exposed configurations instantly."
                  : "Audit entire classes or project batches. Upload CSV lists of student projects, monitor scans in parallel, and export consolidated spreadsheets."
                }
              </p>
            </div>

            {/* SINGLE SCAN INPUT VIEW */}
            {viewMode === "single" && (
              <div className="w-full max-w-xl bg-[#1f2833]/30 border border-[#1f2833] rounded-xl p-6 glow-teal relative">
                <div className="absolute inset-0 scanline opacity-5 rounded-xl pointer-events-none" />
                
                <div className="space-y-4 relative">
                  <div>
                    <label className="block text-xs font-mono uppercase text-cyber-light mb-2">
                      Enter Deployed App URL
                    </label>
                    <div className="flex flex-col sm:flex-row gap-2.5">
                      <div className="flex-grow bg-[#0b0c10]/95 border border-[#1f2833] rounded-lg flex items-center px-3 focus-within:border-cyber-light transition-all">
                        <Globe className="h-4.5 w-4.5 text-cyber-gray/50 shrink-0" />
                        <input 
                          type="text" 
                          value={url}
                          onChange={(e) => setUrl(e.target.value)}
                          placeholder="https://my-student-project.lovable.app"
                          className="w-full bg-transparent border-0 outline-none text-sm py-3 px-2.5 text-white placeholder:text-cyber-gray/40"
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && url && consent) setScanState("scanning");
                          }}
                        />
                      </div>
                      <button
                        onClick={() => setScanState("scanning")}
                        disabled={!url || !consent}
                        className="bg-cyber-light hover:bg-cyber-teal text-cyber-dark font-semibold font-mono text-sm px-6 py-2.5 sm:py-0 rounded-lg transition-all flex items-center justify-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer w-full sm:w-auto"
                      >
                        Audit
                        <ArrowRight className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  {/* Consent Checkbox */}
                  <label className="flex items-start gap-3 select-none cursor-pointer group">
                    <input 
                      type="checkbox"
                      checked={consent}
                      onChange={(e) => setConsent(e.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-[#1f2833] text-cyber-light focus:ring-cyber-light bg-[#0b0c10]"
                    />
                    <span className="text-xs text-cyber-gray/80 group-hover:text-white transition-colors leading-relaxed">
                      I consent to this passive audit. I confirm that I own this project or have explicit authorization to run this security scan.
                    </span>
                  </label>
                </div>
              </div>
            )}

            {/* BATCH AUDIT INPUT VIEW */}
            {viewMode === "batch" && (
              <div className="w-full max-w-2xl bg-[#1f2833]/30 border border-[#1f2833] rounded-xl p-6 glow-teal relative">
                <div className="absolute inset-0 scanline opacity-5 rounded-xl pointer-events-none" />
                
                <div className="space-y-4 relative">
                  
                  {/* Batch Label */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-mono uppercase text-cyber-light mb-1.5">
                        Batch Label / Class Name
                      </label>
                      <input 
                        type="text" 
                        value={batchLabel}
                        onChange={(e) => setBatchLabel(e.target.value)}
                        placeholder="CS Hackathon Spring 2026"
                        className="w-full bg-[#0b0c10]/95 border border-[#1f2833] rounded-lg text-sm py-2 px-3 text-white outline-none focus:border-cyber-light"
                      />
                    </div>
                    
                    {/* CSV Uploader */}
                    <div>
                      <label className="block text-xs font-mono uppercase text-cyber-light mb-1.5">
                        Import URL List via CSV
                      </label>
                      <label className="w-full flex items-center justify-center gap-2 bg-[#0b0c10]/95 border border-dashed border-[#1f2833] rounded-lg py-2 px-3 text-xs text-cyber-gray hover:text-cyber-light hover:border-cyber-light transition-all cursor-pointer">
                        <Upload className="h-4 w-4 shrink-0" />
                        <span>Upload spreadsheet (.csv)</span>
                        <input 
                          type="file" 
                          accept=".csv"
                          onChange={handleCsvUpload}
                          className="hidden"
                        />
                      </label>
                    </div>
                  </div>

                  {/* Target text box URLs */}
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1.5">
                      <label className="uppercase text-cyber-light">
                        Target URLs (One per line, max 50)
                      </label>
                      <span className={`${parsedUrls.length > 50 ? "text-cyber-red" : "text-cyber-gray/50"}`}>
                        {parsedUrls.length} / 50 queued
                      </span>
                    </div>
                    <textarea
                      value={urlTextarea}
                      onChange={(e) => setUrlTextarea(e.target.value)}
                      placeholder="my-student-project1.lovable.app&#10;my-student-project2.bolt.new&#10;https://another-url.vercel.app"
                      rows={6}
                      className="w-full bg-[#0b0c10]/95 border border-[#1f2833] rounded-lg text-xs p-3 text-white outline-none focus:border-cyber-light font-mono"
                    />
                  </div>

                  {/* Live Validation Checklist */}
                  {parsedUrls.length > 0 && (
                    <div className="bg-[#0b0c10]/60 border border-[#1f2833] rounded-lg p-3 max-h-36 overflow-y-auto">
                      <div className="text-[10px] font-mono uppercase text-cyber-light tracking-wide mb-2">// Pre-scan syntax checks</div>
                      <div className="space-y-1.5">
                        {urlChecklist.map((item, idx) => (
                          <div key={idx} className="flex justify-between items-center text-[10px] font-mono">
                            <span className="text-cyber-gray/70 truncate mr-2">{item.url}</span>
                            {item.isValid ? (
                              <span className="text-cyber-green bg-cyber-green/5 border border-cyber-green/20 px-1 py-0.2 rounded shrink-0">PASS</span>
                            ) : (
                              <span className="text-cyber-red bg-cyber-red/5 border border-cyber-red/20 px-1 py-0.2 rounded shrink-0" title={item.reason}>
                                BLOCKED: {item.reason}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Consent and Submit */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pt-2">
                    <label className="flex items-start gap-3 select-none cursor-pointer group max-w-md">
                      <input 
                        type="checkbox"
                        checked={consent}
                        onChange={(e) => setConsent(e.target.checked)}
                        className="mt-1 h-4 w-4 rounded border-[#1f2833] text-cyber-light focus:ring-cyber-light bg-[#0b0c10]"
                      />
                      <span className="text-xs text-cyber-gray/80 group-hover:text-white transition-colors leading-relaxed">
                        I confirm that our organization has permission to pass-scan these targets.
                      </span>
                    </label>
                    
                    <button
                      onClick={startBatchScan}
                      disabled={isBatchSubmitDisabled}
                      className="bg-cyber-light hover:bg-cyber-teal text-cyber-dark font-semibold font-mono text-sm px-6 py-3 rounded-lg transition-all flex items-center justify-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer shrink-0"
                    >
                      Audit Batch
                      <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>

                </div>
              </div>
            )}

            {viewMode === "methodology" && (
              <div className="w-full max-w-3xl bg-[#1f2833]/30 border border-[#1f2833] rounded-xl p-8 glow-teal relative">
                <div className="absolute inset-0 scanline opacity-5 rounded-xl pointer-events-none" />
                
                <h2 className="text-xl font-mono text-cyber-light font-bold mb-4">// Scan Methodology & Rulesets</h2>
                <p className="text-sm text-cyber-gray mb-8">
                  NeuraauditAI runs passive, non-intrusive audits by examining HTTP response headers, probing configuration endpoints, and analyzing client script bundles. Below is the detailed breakdown of the vulnerabilities we check for.
                </p>

                <div className="space-y-6">
                  {/* Category: Secrets */}
                  <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Key className="h-5 w-5 text-red-500" />
                      <h3 className="font-mono text-sm font-semibold text-white">1. Secrets & Key Exposure</h3>
                    </div>
                    <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                      <li><strong>Exposed API Keys:</strong> Scans compiled JavaScript bundles for leaked third-party keys (OpenAI, Anthropic, Gemini, AWS, Mapbox, SendGrid).</li>
                      <li><strong>Supabase service_role Key:</strong> Verifies if the master service key is exposed publicly, which completely bypasses all RLS checks.</li>
                      <li><strong>Stripe Secret Keys:</strong> Flags secret keys (`sk_live_...`) while allowing Stripe publishable keys (`pk_live_...`) as safe.</li>
                    </ul>
                  </div>

                  {/* Category: Database RLS */}
                  <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Database className="h-5 w-5 text-amber-500" />
                      <h3 className="font-mono text-sm font-semibold text-white">2. Database Access Rules</h3>
                    </div>
                    <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                      <li><strong>Supabase RLS Probe:</strong> Dynamically extracts table names from JS bundles (looking for `.from('tableName')`) and queries REST endpoints to test if Row Level Security is disabled.</li>
                      <li><strong>Firebase Firestore Public Read:</strong> Queries Firestore endpoints to verify if user documents are publicly accessible.</li>
                    </ul>
                  </div>

                  {/* Category: Network & Headers */}
                  <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Globe className="h-5 w-5 text-blue-500" />
                      <h3 className="font-mono text-sm font-semibold text-white">3. Network, Transport & Security Headers</h3>
                    </div>
                    <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                      <li><strong>SSL Validity:</strong> Ensures domain SSL certificates are valid, properly configured, and have more than 15 days until expiration.</li>
                      <li><strong>HTTPS Redirection:</strong> Checks if plain HTTP (`http://`) calls are automatically redirected to secure HTTPS.</li>
                      <li><strong>HTTP Security Headers:</strong> Scans for missing `Content-Security-Policy`, `X-Frame-Options` (Clickjacking), `X-Content-Type-Options`, and `Strict-Transport-Security`.</li>
                      <li><strong>Dangerous CORS Settings:</strong> Flags CORS configuration allowing malicious origins to read credentialed responses.</li>
                    </ul>
                  </div>

                  {/* Category: Server files */}
                  <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Server className="h-5 w-5 text-purple-500" />
                      <h3 className="font-mono text-sm font-semibold text-white">4. Exposed Server Configurations</h3>
                    </div>
                    <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                      <li><strong>Static Env Leaks:</strong> Probes common configuration paths like `/.env`, `/.env.local`, and `/config.json`.</li>
                      <li><strong>Git Folder Leaks:</strong> Verifies if the control folder `/.git/config` is accessible, which would allow pulling the whole project source repository.</li>
                      <li><strong>Source Map Exposure:</strong> Flags if `.map` files are published, making full reverse-engineering of the React codebase trivial.</li>
                    </ul>
                  </div>

                  {/* Category: Cookies & Sessions */}
                  <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="h-5 w-5 text-green-500" />
                      <h3 className="font-mono text-sm font-semibold text-white">5. Session & Cache Safety</h3>
                    </div>
                    <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                      <li><strong>Cookie Security Flags:</strong> Validates `Secure`, `HttpOnly`, and `SameSite` flags on all set-cookies.</li>
                      <li><strong>Authentication Caching:</strong> Verifies that `/login` or `/signup` pages send `Cache-Control: no-store` to prevent credentials from being stored in shared browser caches.</li>
                      <li><strong>Legacy Libraries & IDOR:</strong> Detects outdated libraries (e.g. jQuery &lt; 3.5.0) and checks routes for predictable numeric ids (potential IDOR leaks).</li>
                    </ul>
                   </div>

                   {/* Category: AI/LLM Exposure */}
                   <div className="bg-[#0b0c10]/50 border border-[#1f2833]/50 p-5 rounded-lg">
                     <div className="flex items-center gap-2 mb-3">
                       <Brain className="h-5 w-5 text-cyber-light" />
                       <h3 className="font-mono text-sm font-semibold text-white">6. AI & LLM Security</h3>
                     </div>
                     <ul className="space-y-2 text-xs text-cyber-gray/80 ml-7 list-disc">
                       <li><strong>Hardcoded System Prompts:</strong> Analyzes script bundles for long strings (&gt; 150 characters) containing prompt scaffolding patterns that are adjacent (within 1000 characters) to OpenAI, Anthropic, or Gemini host endpoints.</li>
                       <li><strong>GraphQL Introspection Probe:</strong> Discovers GraphQL endpoints on the same origin and tests whether schema introspection queries return full database layouts.</li>
                     </ul>
                   </div>

                   {/* Category: Grading Transparency */}
                   <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-lg">
                     <div className="flex items-center gap-2 mb-3">
                       <ArrowUpDown className="h-5 w-5 text-cyber-light" />
                       <h3 className="font-mono text-sm font-semibold text-white">Grading Algorithm & Severity Rules</h3>
                     </div>
                     <p className="text-xs text-cyber-gray leading-relaxed mb-4">
                       Your overall letter grade (A-F) is derived from a weighted score across all six categories, and then subjected to safety caps based on the highest vulnerability found.
                     </p>
                     
                     <div className="space-y-3 font-mono text-[11px] text-cyber-gray/80 ml-3">
                       <div>
                         <span className="text-white font-bold">// 1. Category Weights:</span>
                         <ul className="list-disc ml-6 mt-1 space-y-1 text-cyber-gray">
                           <li>Secrets (20%) - Critical admin roles and keys leaks.</li>
                           <li>Database (20%) - Open Firestore / Supabase RLS.</li>
                           <li>Network & Transport (15%) - SSL certificate, CSP, headers.</li>
                           <li>AI/LLM Exposure (15%) - Leaked prompts, GraphQL schemas.</li>
                           <li>App Layer (15%) - Cache control, session cookie flags, IDOR.</li>
                           <li>Dependencies (15%) - Vulnerable legacy library update status.</li>
                         </ul>
                       </div>

                       <div>
                         <span className="text-white font-bold">// 2. Safety Grade Caps:</span>
                         <ul className="list-disc ml-6 mt-1 space-y-1 text-cyber-orange">
                           <li>If <strong className="text-cyber-red">1 Critical finding</strong> is detected: The overall grade is capped at <strong className="text-cyber-red">D</strong> (Max score 64) regardless of other perfect categories.</li>
                           <li>If <strong className="text-cyber-orange">1 High finding</strong> is detected: The overall grade is capped at <strong className="text-cyber-orange">C</strong> (Max score 79).</li>
                         </ul>
                       </div>

                       <div>
                         <span className="text-white font-bold">// 3. Threshold Mapping:</span>
                         <ul className="list-disc ml-6 mt-1 space-y-1 text-cyber-gray">
                           <li>90+ Overall Weighted Score ➔ Grade A</li>
                           <li>80 - 89 Score ➔ Grade B</li>
                           <li>65 - 79 Score ➔ Grade C</li>
                           <li>50 - 64 Score ➔ Grade D</li>
                           <li>Below 50 Score ➔ Grade F</li>
                         </ul>
                       </div>
                     </div>
                   </div>

                 </div>
               </div>
             )}

            {viewMode !== "methodology" && (
              <div className="w-full max-w-4xl mt-16 pt-10 border-t border-[#1f2833]/40 space-y-8">
                <div className="flex justify-between items-center border-b border-[#1f2833]/40 pb-4">
                  <h2 className="text-xl font-mono text-cyber-light font-bold flex items-center gap-2">
                    <Clock className="h-5 w-5" /> // Audit History Logs
                  </h2>
                  <button
                    onClick={fetchHistory}
                    disabled={loadingHistory}
                    className="flex items-center gap-1.5 text-xs font-mono text-cyber-light hover:text-white bg-cyber-light/5 border border-cyber-light/20 px-3 py-1.5 rounded transition-all cursor-pointer"
                  >
                    <RefreshCw className={`h-3 w-3 ${loadingHistory ? "animate-spin" : ""}`} />
                    Refresh Logs
                  </button>
                </div>

                {loadingHistory ? (
                  <div className="flex flex-col items-center py-16">
                    <RefreshCw className="h-8 w-8 text-cyber-light animate-spin mb-3" />
                    <p className="text-sm font-mono text-cyber-gray/60">Retrieving audit history...</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    
                    {/* Left Column: Individual Audits */}
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <h3 className="font-mono text-xs uppercase text-cyber-light font-semibold tracking-wider">// Individual Audits ({historyData.scans.length})</h3>
                      </div>
                      
                      {historyData.scans.length === 0 ? (
                        <div className="bg-[#1f2833]/10 border border-[#1f2833]/30 rounded-xl p-8 text-center">
                          <Globe className="h-8 w-8 text-cyber-gray/40 mx-auto mb-3" />
                          <p className="text-xs text-cyber-gray/60">No individual scan records found.</p>
                        </div>
                      ) : (
                        <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                          {historyData.scans.map((scan, idx) => {
                            const gradeColor = 
                              scan.latestResult.grade === "A" ? "text-[#10b981] border-[#10b981]/20 bg-[#10b981]/5" :
                              scan.latestResult.grade === "B" ? "text-[#66fcf1] border-[#66fcf1]/20 bg-[#66fcf1]/5" :
                              scan.latestResult.grade === "C" ? "text-[#f59e0b] border-[#f59e0b]/20 bg-[#f59e0b]/5" :
                              "text-[#ef4444] border-[#ef4444]/20 bg-[#ef4444]/5";

                            return (
                              <div key={idx} className="bg-[#1f2833]/20 border border-[#1f2833]/50 rounded-lg p-4 hover:border-cyber-light/40 transition-all flex items-center justify-between gap-4">
                                <div className="min-w-0">
                                  <div className="text-xs font-semibold text-white truncate" title={scan.url}>
                                    {scan.url}
                                  </div>
                                  <div className="text-[10px] text-cyber-gray/50 font-mono mt-1">
                                    Scanned: {new Date(scan.timestamp).toLocaleString()} ({scan.historyCount} run{scan.historyCount > 1 ? "s" : ""})
                                  </div>
                                </div>
                                <div className="flex items-center gap-3 shrink-0">
                                  <span className={`h-8 w-8 rounded-full border flex items-center justify-center font-bold text-sm ${gradeColor}`}>
                                    {scan.latestResult.grade || "F"}
                                  </span>
                                  <button
                                    onClick={() => handleLoadPastScan(scan.latestResult)}
                                    className="p-1.5 rounded bg-cyber-light/10 text-cyber-light hover:bg-cyber-light hover:text-cyber-dark transition-all cursor-pointer flex items-center justify-center"
                                    title="View Report"
                                  >
                                    <ArrowRight className="h-4 w-4" />
                                  </button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {/* Right Column: Batch Audits */}
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <h3 className="font-mono text-xs uppercase text-cyber-light font-semibold tracking-wider">// Batch Audits ({historyData.batches.length})</h3>
                      </div>
                      
                      {historyData.batches.length === 0 ? (
                        <div className="bg-[#1f2833]/10 border border-[#1f2833]/30 rounded-xl p-8 text-center">
                          <Grid className="h-8 w-8 text-cyber-gray/40 mx-auto mb-3" />
                          <p className="text-xs text-cyber-gray/60">No batch scan records found.</p>
                        </div>
                      ) : (
                        <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                          {historyData.batches.map((batch, idx) => {
                            const statusColor = 
                              batch.status === "completed" ? "text-cyber-green bg-cyber-green/5 border-cyber-green/20" :
                              batch.status === "failed" ? "text-cyber-red bg-cyber-red/5 border-cyber-red/20" :
                              "text-cyber-orange bg-cyber-orange/5 border-cyber-orange/20";

                            return (
                              <div key={idx} className="bg-[#1f2833]/20 border border-[#1f2833]/50 rounded-lg p-4 hover:border-cyber-light/40 transition-all flex items-center justify-between gap-4">
                                <div className="min-w-0">
                                  <div className="text-xs font-semibold text-white truncate">
                                    {batch.label || "Unnamed Batch"}
                                  </div>
                                  <div className="text-[10px] text-cyber-gray/50 font-mono mt-1">
                                    Created: {new Date(batch.createdAt).toLocaleString()} | {batch.total} URL{batch.total > 1 ? "s" : ""}
                                  </div>
                                </div>
                                <div className="flex items-center gap-3 shrink-0">
                                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${statusColor}`}>
                                    {batch.status}
                                  </span>
                                  <button
                                    onClick={() => handleLoadPastBatch(batch.batchId)}
                                    className="p-1.5 rounded bg-cyber-light/10 text-cyber-light hover:bg-cyber-light hover:text-cyber-dark transition-all cursor-pointer flex items-center justify-center"
                                    title="View Batch Report"
                                  >
                                    <ArrowRight className="h-4 w-4" />
                                  </button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                  </div>
                )}
              </div>
            )}

            {viewMode !== "methodology" && (
              <>
            {/* Test Targets Hint */}
            <div className="mt-6 flex flex-wrap gap-2 items-center justify-center text-xs">
              <span className="text-cyber-gray/50 font-mono">// Safe test sites:</span>
              <button 
                onClick={() => {
                  if (viewMode === "single") setUrl("https://example.com");
                  else setUrlTextarea("https://example.com\nhttps://google.com");
                  setConsent(true);
                }}
                className="font-mono text-cyber-light hover:underline"
              >
                example.com
              </button>
              <span className="text-cyber-gray/30">|</span>
              <button 
                onClick={() => {
                  if (viewMode === "single") setUrl("https://google.com");
                  else setUrlTextarea("https://example.com\nhttps://google.com");
                  setConsent(true);
                }}
                className="font-mono text-cyber-light hover:underline"
              >
                google.com
              </button>
            </div>

            {/* Features Breakdown */}
            <section id="what-we-check" className="w-full mt-20 pt-10 border-t border-[#1f2833]/40">
              <div className="text-center mb-8">
                <h2 className="font-mono text-sm uppercase text-cyber-light tracking-wider">// Deep-Scan Capabilities</h2>
                <p className="text-lg font-bold text-white mt-1">What NeuraauditAI Analyzes Passively</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                <div className="bg-[#1f2833]/15 border border-[#1f2833]/60 p-5 rounded-lg">
                  <div className="h-9 w-9 rounded bg-[#ea580c]/10 flex items-center justify-center mb-4">
                    <Lock className="h-5 w-5 text-[#ea580c]" />
                  </div>
                  <h3 className="text-sm font-semibold text-white">Secrets Exposure</h3>
                  <p className="mt-2 text-xs text-cyber-gray/70 leading-relaxed">
                    Checks compiled client bundles for exposed API keys (OpenAI, Anthropic, Gemini, AWS, Stripe secrets) and warns if they are vulnerable to direct extraction.
                  </p>
                </div>

                <div className="bg-[#1f2833]/15 border border-[#1f2833]/60 p-5 rounded-lg">
                  <div className="h-9 w-9 rounded bg-[#ef4444]/10 flex items-center justify-center mb-4">
                    <Database className="h-5 w-5 text-[#ef4444]" />
                  </div>
                  <h3 className="text-sm font-semibold text-white">Database Rules (RLS)</h3>
                  <p className="mt-2 text-xs text-cyber-gray/70 leading-relaxed">
                    Detects Supabase or Firebase configurations and probes endpoints to test if Row Level Security is disabled on sensitive client tables.
                  </p>
                </div>

                <div className="bg-[#1f2833]/15 border border-[#1f2833]/60 p-5 rounded-lg">
                  <div className="h-9 w-9 rounded bg-[#3b82f6]/10 flex items-center justify-center mb-4">
                    <Grid className="h-5 w-5 text-[#3b82f6]" />
                  </div>
                  <h3 className="text-sm font-semibold text-white">Network & Transport</h3>
                  <p className="mt-2 text-xs text-cyber-gray/70 leading-relaxed">
                    Evaluates SSL certificate lifetimes, checks HTTP-to-HTTPS redirection, and scans for critical headers like CSP, Clickjacking protection, and CORS.
                  </p>
                </div>
              </div>
            </section>
              </>
            )}

          </div>
        )}

        {/* SINGLE SCANNING PROGRESS SCREEN */}
        {scanState === "scanning" && (
          <div className="w-full max-w-xl px-4 py-16 flex flex-col items-center">
            
            <div className="relative h-24 w-24 rounded-full border border-cyber-light/20 flex items-center justify-center mb-10">
              <div className="absolute inset-0 rounded-full border border-cyber-light/40 animate-ping opacity-25" />
              <div className="absolute inset-4 rounded-full border border-cyber-teal/30 animate-pulse" />
              <RefreshCw className="h-8 w-8 text-cyber-light animate-spin" />
            </div>

            <div className="text-center mb-8">
              <h2 className="text-lg font-bold text-white tracking-tight">Scanner Running...</h2>
              <p className="text-xs text-cyber-gray/60 font-mono mt-1">AUDITING TARGET: {url}</p>
            </div>

            <div className="w-full bg-[#1f2833]/20 border border-[#1f2833] rounded-lg p-5 divide-y divide-[#1f2833]/40 space-y-3 font-mono">
              {stepStatuses.map((step, idx) => (
                <div 
                  key={step.key} 
                  className={`flex items-center justify-between text-xs py-2.5 transition-colors ${
                    idx === currentStepIndex ? "text-cyber-light" : "text-cyber-gray/60"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-cyber-gray/30">0{idx + 1}.</span>
                    <span>{step.name}</span>
                  </div>
                  
                  {step.status === "pending" && <span className="text-cyber-gray/30">[ QUEUED ]</span>}
                  {step.status === "running" && <span className="text-cyber-light animate-pulse font-bold">[ RUNNING ]</span>}
                  {step.status === "pass" && (
                    <span className="text-cyber-green flex items-center gap-1">
                      <CheckCircle className="h-3.5 w-3.5" /> [ SAFE ]
                    </span>
                  )}
                  {step.status === "fail" && (
                    <span className="text-cyber-red flex items-center gap-1 font-bold">
                      <AlertTriangle className="h-3.5 w-3.5" /> [ FLAG ]
                    </span>
                  )}
                </div>
              ))}
            </div>

          </div>
        )}

        {/* BATCH SCANNING PROGRESS SCREEN */}
        {scanState === "batch-scanning" && (
          <div className="w-full max-w-3xl px-4 py-12">
            
            <div className="flex flex-col md:flex-row items-center justify-between gap-6 border-b border-[#1f2833] pb-6 mb-8">
              <div>
                <span className="font-mono text-xs text-cyber-light tracking-wide uppercase">// Batch Audit In Progress</span>
                <h2 className="text-2xl font-bold text-white tracking-tight mt-1">
                  {batchProgress?.label || "Processing Queue..."}
                </h2>
                <div className="flex items-center gap-2 mt-2">
                  <span className="h-2 w-2 rounded-full bg-cyber-light animate-pulse-dot" />
                  <span className="text-xs text-cyber-gray/60 font-mono">
                    Completed: {batchProgress?.completed || 0} / {batchProgress?.total || 0}
                  </span>
                  {batchProgress?.failed > 0 && (
                    <span className="text-xs text-cyber-red font-mono ml-2">
                      Failed: {batchProgress.failed}
                    </span>
                  )}
                </div>
              </div>

              {/* Mini Loader */}
              <div className="flex items-center gap-3 bg-[#1f2833]/30 border border-[#1f2833] rounded-lg px-4 py-3 shrink-0">
                <RefreshCw className="h-5 w-5 text-cyber-light animate-spin" />
                <div className="font-mono text-xs text-left">
                  <div className="text-white font-bold">Queue Active</div>
                  <div className="text-cyber-gray/50">Concurrency Limit: 3</div>
                </div>
              </div>
            </div>

            {/* URL Status Progress Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-2">
              {batchProgress?.results.map((proj, idx) => (
                <div 
                  key={idx} 
                  className={`bg-[#1f2833]/15 border p-3 rounded-lg flex items-center justify-between transition-all ${
                    proj.status === "scanning" 
                      ? "border-cyber-light bg-cyber-light/5" 
                      : proj.status === "done" 
                      ? "border-cyber-green/30" 
                      : proj.status === "failed" 
                      ? "border-cyber-red/30" 
                      : "border-[#1f2833]/60"
                  }`}
                >
                  <div className="flex flex-col min-w-0 pr-3">
                    <span className="text-[10px] font-mono text-cyber-gray/40 truncate">{proj.url}</span>
                    {proj.status === "scanning" && (
                      <span className="text-[10px] text-cyber-light font-mono animate-pulse mt-0.5">Auditing assets...</span>
                    )}
                    {proj.status === "failed" && (
                      <span className="text-[10px] text-cyber-red font-mono truncate mt-0.5" title={proj.error}>
                        Error: {proj.error || "Blocked IP/SSRF"}
                      </span>
                    )}
                    {proj.status === "queued" && (
                      <span className="text-[10px] text-cyber-gray/40 font-mono mt-0.5">Queued</span>
                    )}
                    {proj.status === "done" && (
                      <span className="text-[10px] text-cyber-green font-mono mt-0.5">Scan complete</span>
                    )}
                  </div>

                  {/* Status Badges */}
                  <div className="shrink-0 font-mono text-[10px] uppercase font-bold">
                    {proj.status === "queued" && (
                      <span className="text-cyber-gray/40 border border-[#1f2833] px-2 py-0.5 rounded">Queued</span>
                    )}
                    {proj.status === "scanning" && (
                      <span className="text-cyber-light border border-cyber-light/40 px-2 py-0.5 rounded animate-pulse">Running</span>
                    )}
                    {proj.status === "failed" && (
                      <span className="text-cyber-red border border-cyber-red/40 px-2 py-0.5 rounded">Failed</span>
                    )}
                    {proj.status === "done" && (
                      <span className={`border px-2.5 py-0.5 rounded text-[11px] ${
                        proj.grade === "A" 
                          ? "border-cyber-green/40 text-cyber-green bg-cyber-green/10" 
                          : proj.grade === "B" 
                          ? "border-cyber-light/40 text-cyber-light bg-cyber-light/10"
                          : proj.grade === "C" || proj.grade === "D"
                          ? "border-cyber-orange/40 text-cyber-orange bg-cyber-orange/10"
                          : "border-cyber-red/40 text-cyber-red bg-cyber-red/10"
                      }`}>
                        Grade {proj.grade}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

          </div>
        )}

        {/* SINGLE RESULT VIEW */}
        {scanState === "results" && scanResults && (
          <div className="w-full max-w-5xl px-4 py-8 flex flex-col md:flex-row gap-6">
            
            {/* Sidebar Overview */}
            <div className="w-full md:w-80 shrink-0 space-y-6">
              
              {/* Score / Grade Card */}
              <div className={`p-6 rounded-xl border ${gradeInfo.border} ${gradeInfo.bg} flex flex-col items-center text-center relative overflow-hidden`}>
                <div className="absolute inset-0 scanline opacity-3 pointer-events-none" />
                <span className="text-xs font-mono uppercase tracking-wider text-cyber-gray/70">Security Posture</span>
                
                <div className="h-28 w-28 rounded-full border-4 border-current flex items-center justify-center my-4 font-mono text-5xl font-extrabold shadow-inner select-none glow-teal">
                  <span className={gradeInfo.color}>{gradeInfo.grade}</span>
                </div>

                <h3 className={`text-base font-bold uppercase tracking-tight ${gradeInfo.color}`}>{gradeInfo.label}</h3>
                <p className="text-xs text-cyber-gray/60 mt-1 leading-normal">
                  Passive audit detected {displayedResults.findings.length} findings on target host.
                </p>

                {/* Why This Grade? Expandable Section */}
                <div className="w-full mt-4 pt-3 border-t border-[#1f2833]/40 text-left">
                  <button
                    onClick={() => setWhyGradeExpanded(!whyGradeExpanded)}
                    className="w-full flex items-center justify-between text-xs font-mono text-cyber-light hover:text-white transition-colors cursor-pointer select-none outline-none"
                  >
                    <span>Why This Grade?</span>
                    <span>{whyGradeExpanded ? "▲" : "▼"}</span>
                  </button>

                  {whyGradeExpanded && (
                    <div className="mt-3 space-y-3 text-xs text-cyber-gray/90 leading-relaxed font-sans">
                      {/* 1. Cap applied display */}
                      {displayedResults.capApplied && (
                        <div className="p-2.5 rounded border border-cyber-red/30 bg-cyber-red/5 text-cyber-red font-mono text-[10px] uppercase leading-normal">
                          ⚠️ {displayedResults.capReason}
                        </div>
                      )}

                      {/* 2. Plain English Breakdown summary */}
                      <p className="text-[11px]">
                        {(() => {
                          const breakdown = displayedResults.weightedBreakdown || [];
                          if (breakdown.length === 0) return "Your grade is determined based on the default server security scanner policy.";
                          
                          const weakCategories = breakdown.filter(cat => cat.score < 80);
                          const perfectCategories = breakdown.filter(cat => cat.score === 100);

                          let explanationStr = `Your grade is ${displayedResults.grade} (Overall Score: ${displayedResults.overallScore || 0}/100) based on weighted category scores. `;
                          
                          if (weakCategories.length > 0) {
                            explanationStr += `It is pulled down primarily by your ${weakCategories.map(c => `${c.category} (${c.score}/100)`).join(", ")} score${weakCategories.length > 1 ? "s" : ""}. `;
                          }
                          if (perfectCategories.length > 0 && weakCategories.length > 0) {
                            explanationStr += `Even though categories like ${perfectCategories.map(c => c.category).join(", ")} are perfect, weaker sections reduce the overall rating.`;
                          } else if (perfectCategories.length === breakdown.length) {
                            explanationStr += "All of your security categories are in a perfect, secure state!";
                          }

                          return explanationStr;
                        })()}
                      </p>

                      {/* 3. Category Score Weight Proportion Bars */}
                      <div className="space-y-2 pt-2 border-t border-[#1f2833]/20 font-mono text-[10px]">
                        <span className="text-[9px] uppercase tracking-wider text-cyber-gray/50">// Category Weights:</span>
                        {categoryScores.map(cat => {
                          const pct = cat.weight ? Math.round(cat.weight * 100) : 15;
                          return (
                            <div key={cat.name} className="space-y-1">
                              <div className="flex justify-between text-[9px] text-cyber-gray/70">
                                <span>{cat.name} (Weight: {pct}%)</span>
                                <span>{cat.score}/100</span>
                              </div>
                              <div className="h-1 bg-[#1f2833] rounded-full overflow-hidden">
                                <div 
                                  className="h-full bg-cyber-light/40" 
                                  style={{ width: `${cat.score}%` }} 
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-[#1f2833]/40 w-full flex justify-between text-[10px] font-mono text-cyber-gray/50">
                  <span>PLATFORM: {displayedResults.platformDetected}</span>
                  <span>TIME: {displayedResults.scanDurationMs}ms</span>
                </div>
              </div>

              {/* Category Scores */}
              <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl">
                <h4 className="text-xs font-mono uppercase text-cyber-light mb-4 tracking-wider">// Score breakdown</h4>
                <div className="space-y-4">
                  {categoryScores.map(cat => (
                    <div key={cat.name} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-cyber-gray">{cat.name}</span>
                        <span className={cat.score >= 80 ? "text-cyber-green" : cat.score >= 50 ? "text-cyber-orange" : "text-cyber-red"}>
                          {cat.score}/100
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-[#0b0c10] rounded-full overflow-hidden border border-[#1f2833]/50">
                        <div 
                          className={`h-full rounded-full transition-all duration-1000 ${
                            cat.score >= 80 ? "bg-cyber-green" : cat.score >= 50 ? "bg-cyber-orange" : "bg-cyber-red"
                          }`}
                          style={{ width: `${cat.score}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex flex-col gap-2.5">
                <button
                  onClick={handlePrint}
                  className="w-full flex items-center justify-center gap-2 bg-[#1f2833] hover:bg-[#1f2833]/80 text-white font-mono text-xs py-2.5 px-4 rounded-lg border border-[#1f2833] transition-all cursor-pointer"
                >
                  <Download className="h-4 w-4" /> Download PDF Report
                </button>
                <button
                  onClick={() => {
                    setScanResults(null);
                    setScanState("landing");
                  }}
                  className="w-full flex items-center justify-center gap-2 bg-transparent hover:bg-[#1f2833]/20 text-cyber-light font-mono text-xs py-2.5 px-4 rounded-lg border border-cyber-light/30 transition-all cursor-pointer"
                >
                  <RefreshCw className="h-4 w-4" /> Run Another Audit
                </button>
              </div>

              {/* Email Capture */}
              <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl">
                <h4 className="text-xs font-mono uppercase text-cyber-light mb-2 tracking-wider">// Share results</h4>
                <p className="text-[10px] text-cyber-gray/70 leading-relaxed mb-3">
                  Send this security report directly to your inbox or share with team members.
                </p>
                <form onSubmit={handleEmailReport} className="space-y-2">
                  <input 
                    type="email" 
                    placeholder="student@college.edu"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-[#0b0c10] border border-[#1f2833] rounded px-2.5 py-1.5 text-xs text-white placeholder:text-cyber-gray/30 outline-none focus:border-cyber-light"
                  />
                  <button
                    type="submit"
                    className="w-full bg-cyber-light/10 hover:bg-cyber-light/20 text-cyber-light border border-cyber-light/30 font-mono text-xs py-1.5 rounded transition-all cursor-pointer"
                  >
                    Email Me Report
                  </button>
                </form>
                {emailSent && (
                  <p className="text-[10px] text-cyber-green font-mono mt-2 flex items-center gap-1">
                    <CheckCircle className="h-3 w-3" /> Report queued! Check inbox shortly.
                  </p>
                )}
              </div>

              {/* Scan History Timeline */}
              {scanResults.history && scanResults.history.length > 0 && (
                <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl">
                  <h4 className="text-xs font-mono uppercase text-cyber-light mb-4 tracking-wider flex items-center gap-1.5">
                    <BookOpen className="h-4 w-4" /> Scan History
                  </h4>
                  
                  <div className="space-y-4 relative before:absolute before:left-2 before:top-2 before:bottom-2 before:w-[1px] before:bg-[#1f2833] pl-1">
                    {/* Latest Run Node */}
                    <div className="flex items-start gap-3 relative">
                      <div 
                        onClick={() => setActiveHistoryIndex(null)}
                        className={`h-3 w-3 rounded-full border-2 shrink-0 z-10 cursor-pointer transition-all ${
                          activeHistoryIndex === null 
                            ? "bg-cyber-light border-cyber-light scale-110 shadow-lg shadow-cyber-light/30" 
                            : "bg-[#0b0c10] border-[#1f2833] hover:border-cyber-light"
                        }`}
                      />
                      <div className="flex-grow min-w-0">
                        <button
                          onClick={() => setActiveHistoryIndex(null)}
                          className={`text-xs font-mono block text-left cursor-pointer transition-colors ${
                            activeHistoryIndex === null ? "text-cyber-light font-bold" : "text-cyber-gray hover:text-white"
                          }`}
                        >
                          Latest Run
                        </button>
                        <span className="text-[10px] text-cyber-gray/50 block mt-0.5">
                          {new Date(scanResults.scannedAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>

                    {/* Past Runs Nodes */}
                    {scanResults.history.map((run, idx) => {
                      const runGrade = getGradeForFindings(run.result.findings);
                      
                      return (
                        <div key={idx} className="flex items-start gap-3 relative">
                          <div 
                            onClick={() => setActiveHistoryIndex(idx)}
                            className={`h-3 w-3 rounded-full border-2 shrink-0 z-10 cursor-pointer transition-all ${
                              activeHistoryIndex === idx 
                                ? "bg-cyber-light border-cyber-light scale-110 shadow-lg shadow-cyber-light/30" 
                                : "bg-[#0b0c10] border-[#1f2833] hover:border-cyber-light"
                            }`}
                          />
                          <div className="flex-grow min-w-0">
                            <button
                              onClick={() => setActiveHistoryIndex(idx)}
                              className={`text-xs font-mono block text-left cursor-pointer transition-colors ${
                                activeHistoryIndex === idx ? "text-cyber-light font-bold" : "text-cyber-gray hover:text-white"
                              }`}
                            >
                              Run #{scanResults.history.length - idx} (Grade {runGrade})
                            </button>
                            <span className="text-[10px] text-cyber-gray/50 block mt-0.5">
                              {new Date(run.timestamp).toLocaleDateString()}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

            </div>

            {/* Findings List */}
            <div className="flex-grow space-y-4">
              {/* Diff / Improvement Tracker Banner */}
              {activeHistoryIndex === null && scanResults.diff && (
                <div className="p-4 rounded-xl border border-cyber-green/30 bg-cyber-green/5 flex items-start gap-3 relative overflow-hidden">
                  <div className="absolute inset-y-0 left-0 w-1 bg-cyber-green" />
                  <div className="mt-0.5">
                    <Shield className="h-5 w-5 text-cyber-green animate-pulse" />
                  </div>
                  <div className="flex-grow min-w-0">
                    <h4 className="text-sm font-bold text-white tracking-tight">
                      🛡️ Security Posture Update
                    </h4>
                    <p className="text-xs text-cyber-gray/95 mt-1 leading-relaxed">
                      {scanResults.diff.gradeDiff ? (
                        <>
                          Your grade improved from <strong className="text-cyber-red">{scanResults.diff.previousGrade}</strong> to <strong className="text-cyber-green">{scanResults.diff.currentGrade}</strong>!{" "}
                        </>
                      ) : (
                        <>
                          Your grade remained at <strong className="text-cyber-light">{scanResults.diff.currentGrade}</strong>.{" "}
                        </>
                      )}
                      We detected <strong className="text-cyber-green">{scanResults.diff.resolvedCount} issues resolved</strong>
                      {scanResults.diff.newCount > 0 && (
                        <> and <strong className="text-cyber-orange">{scanResults.diff.newCount} new issues</strong></>
                      )}
                      . Keep up the good work!
                    </p>
                  </div>
                </div>
              )}

              {/* Viewing History Mode Banner */}
              {activeHistoryIndex !== null && (
                <div className="p-4 rounded-xl border border-cyber-light/30 bg-cyber-light/5 flex items-center justify-between gap-3 relative overflow-hidden">
                  <div className="absolute inset-y-0 left-0 w-1 bg-cyber-light" />
                  <div className="flex items-center gap-2">
                    <RefreshCw className="h-4 w-4 text-cyber-light animate-spin" style={{ animationDuration: '6s' }} />
                    <span className="text-xs font-mono text-white">
                      Viewing past audit run from {new Date(scanResults.history[activeHistoryIndex].timestamp).toLocaleString()}
                    </span>
                  </div>
                  <button
                    onClick={() => setActiveHistoryIndex(null)}
                    className="text-xs font-mono font-bold text-cyber-light hover:underline cursor-pointer"
                  >
                    Back to Latest Run ➔
                  </button>
                </div>
              )}

              <div className="flex items-center justify-between border-b border-[#1f2833] pb-3">
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight">Audit Findings</h2>
                  <p className="text-xs text-cyber-gray/60 mt-0.5">TARGET URL: {displayedResults.url}</p>
                </div>
                <span className="font-mono text-xs bg-[#1f2833]/40 border border-[#1f2833] px-2.5 py-1 rounded text-cyber-light">
                  {displayedResults.findings.length} issues flagged
                </span>
              </div>

              {displayedResults.findings.length === 0 ? (
                <div className="bg-[#10b981]/5 border border-[#10b981]/20 rounded-xl p-8 text-center flex flex-col items-center">
                  <CheckCircle className="h-12 w-12 text-[#10b981] mb-3" />
                  <h3 className="text-base font-bold text-white">No Vulnerabilities Detected</h3>
                  <p className="text-xs text-cyber-gray/70 mt-1 max-w-md">
                    NeuraauditAI didn't find any exposed keys, open databases, or missing security headers. Your project is looking clean and ready for demo day!
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {displayedResults.findings.sort((a,b) => {
                    const severities = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                    return severities[b.severity] - severities[a.severity];
                  }).map(finding => (
                    <FindingCard 
                      key={finding.id} 
                      finding={finding} 
                      onCopyPrompt={handleCopyPrompt}
                      copiedId={copiedId}
                    />
                  ))}
                </div>
              )}
            </div>

          </div>
        )}

        {/* BATCH RESULTS VIEW */}
        {scanState === "batch-results" && batchResults && (
          <div className="w-full max-w-5xl px-4 py-8 space-y-6">
            
            {/* Batch Header Stats Summary */}
            <div className="flex flex-col md:flex-row items-start justify-between gap-6 border-b border-[#1f2833] pb-6">
              <div>
                <span className="font-mono text-xs text-cyber-light tracking-wide uppercase">// Consolidated Batch Audit Results</span>
                <h2 className="text-3xl font-extrabold text-white tracking-tight mt-1">
                  {batchResults.label}
                </h2>
                <p className="text-xs text-cyber-gray/60 mt-1 font-mono">
                  CREATED AT: {new Date(batchResults.createdAt).toLocaleString()} &bull; TOTAL PROJECTS AUDITED: {batchResults.total}
                </p>
              </div>

              <div className="flex flex-wrap gap-3 shrink-0">
                <button
                  onClick={exportBatchCsv}
                  className="flex items-center gap-2 bg-[#1f2833] hover:bg-[#1f2833]/85 text-white border border-[#1f2833] font-mono text-xs py-2 px-4 rounded-lg transition-all cursor-pointer"
                >
                  <Download className="h-4 w-4" /> Export CSV Summary
                </button>
                <button
                  onClick={handlePrint}
                  className="flex items-center gap-2 bg-[#1f2833] hover:bg-[#1f2833]/85 text-white border border-[#1f2833] font-mono text-xs py-2 px-4 rounded-lg transition-all cursor-pointer"
                >
                  <FileText className="h-4 w-4" /> Print Reports Layout
                </button>
                <button
                  onClick={() => {
                    setBatchResults(null);
                    setScanState("landing");
                  }}
                  className="flex items-center gap-2 bg-transparent hover:bg-[#1f2833]/20 text-cyber-light border border-cyber-light/30 font-mono text-xs py-2 px-4 rounded-lg transition-all cursor-pointer"
                >
                  <RefreshCw className="h-4 w-4" /> Reset
                </button>
              </div>
            </div>

            {/* Dashboard Row: Grade Circle, Distribution Bar, Top Vulnerability */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              
              {/* Average Grade Circle */}
              <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl flex items-center justify-between">
                <div>
                  <h4 className="text-[10px] font-mono text-cyber-light uppercase tracking-wider">// Class Average</h4>
                  <div className="text-[10px] text-cyber-gray/60 font-mono mt-1">Based on GPA weighting</div>
                </div>
                
                <div className={`h-16 w-16 rounded-full border-4 border-current flex items-center justify-center font-mono text-2xl font-black shadow-inner select-none glow-teal ${
                  batchResults.stats.averageGrade === "A" 
                    ? "text-cyber-green bg-cyber-green/5" 
                    : batchResults.stats.averageGrade === "B"
                    ? "text-cyber-light bg-cyber-light/5"
                    : batchResults.stats.averageGrade === "C" || batchResults.stats.averageGrade === "D"
                    ? "text-cyber-orange bg-cyber-orange/5"
                    : "text-cyber-red bg-cyber-red/5"
                }`}>
                  {batchResults.stats.averageGrade || "F"}
                </div>
              </div>

              {/* Grade Distribution */}
              <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl">
                <h4 className="text-[10px] font-mono text-cyber-light uppercase tracking-wider mb-3">// Grade Distribution</h4>
                <div className="flex items-end gap-1.5 h-16 pt-2 select-none">
                  {Object.entries(batchResults.stats.distribution).map(([letter, count]) => {
                    const total = batchResults.total || 1;
                    const percent = Math.round((count / total) * 100);
                    return (
                      <div key={letter} className="flex-1 flex flex-col items-center justify-end h-full group relative">
                        <div 
                          className={`w-full rounded-t transition-all duration-1000 ${
                            letter === "A" 
                              ? "bg-cyber-green" 
                              : letter === "B"
                              ? "bg-cyber-light"
                              : letter === "C" || letter === "D"
                              ? "bg-cyber-orange"
                              : "bg-cyber-red"
                          }`}
                          style={{ height: `${Math.max(12, percent)}%` }}
                        />
                        <span className="text-[9px] font-mono text-cyber-gray/60 mt-1.5">{letter}({count})</span>
                        
                        {/* Hover Tooltip */}
                        <div className="absolute bottom-full mb-1 bg-[#0b0c10] border border-[#1f2833] px-2 py-0.5 rounded text-[8px] font-mono text-white opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                          {percent}% ({count})
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Top Vulnerability Banner */}
              <div className="bg-[#1f2833]/15 border border-[#1f2833] p-5 rounded-xl flex flex-col justify-between">
                <div>
                  <h4 className="text-[10px] font-mono text-cyber-light uppercase tracking-wider">// Top Vulnerability</h4>
                  {batchResults.stats.commonFindings && batchResults.stats.commonFindings.length > 0 ? (
                    <div className="mt-2">
                      <div className="text-white text-xs font-bold truncate leading-tight">
                        {batchResults.stats.commonFindings[0].title}
                      </div>
                      <div className="text-[10px] text-cyber-gray/70 font-mono mt-1">
                        Affects {batchResults.stats.commonFindings[0].count} of {batchResults.total} projects in this batch.
                      </div>
                    </div>
                  ) : (
                    <div className="text-[11px] text-cyber-gray/50 font-mono mt-3">No vulnerabilities detected in this batch.</div>
                  )}
                </div>
                
                {batchResults.stats.commonFindings && batchResults.stats.commonFindings.length > 0 && (
                  <div className="text-[9px] font-mono text-[#f59e0b] border border-[#f59e0b]/20 bg-[#f59e0b]/5 px-2 py-0.5 rounded w-fit mt-2">
                    REMEDIATION SUGGESTED
                  </div>
                )}
              </div>

            </div>

            {/* Sortable Projects Table */}
            <div className="bg-[#1f2833]/15 border border-[#1f2833] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1f2833] flex justify-between items-center bg-[#1f2833]/30">
                <span className="font-mono text-xs uppercase text-cyber-light tracking-wide">// Audited Projects</span>
                <span className="font-mono text-[10px] text-cyber-gray/40">Click rows to view full details</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-[#1f2833] text-cyber-light bg-[#0b0c10]/40">
                      <th 
                        onClick={() => handleSort("url")}
                        className="p-3.5 cursor-pointer hover:bg-[#1f2833]/20 select-none w-[50%]"
                      >
                        <div className="flex items-center gap-1.5">
                          Target URL <ArrowUpDown className="h-3 w-3" />
                        </div>
                      </th>
                      <th 
                        onClick={() => handleSort("grade")}
                        className="p-3.5 cursor-pointer hover:bg-[#1f2833]/20 select-none text-center"
                      >
                        <div className="flex items-center justify-center gap-1.5">
                          Grade <ArrowUpDown className="h-3 w-3" />
                        </div>
                      </th>
                      <th 
                        onClick={() => handleSort("findingsCount")}
                        className="p-3.5 cursor-pointer hover:bg-[#1f2833]/20 select-none text-center"
                      >
                        <div className="flex items-center justify-center gap-1.5">
                          Issues <ArrowUpDown className="h-3 w-3" />
                        </div>
                      </th>
                      <th className="p-3.5 text-center">Top Severity</th>
                      <th className="p-3.5 text-center">Platform</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedBatchProjects.map((p, index) => {
                      const isExpanded = expandedProjectUrl === p.url;
                      const hasFailed = p.status === "failed";
                      
                      // Calculate top severity
                      let topSeverity = "NONE";
                      let severityColor = "text-cyber-green";
                      
                      if (p.findings && p.findings.length > 0) {
                        if (p.findings.some(f => f.severity === "critical")) {
                          topSeverity = "CRITICAL";
                          severityColor = "text-cyber-red";
                        } else if (p.findings.some(f => f.severity === "high")) {
                          topSeverity = "HIGH";
                          severityColor = "text-[#f59e0b]";
                        } else if (p.findings.some(f => f.severity === "medium")) {
                          topSeverity = "MEDIUM";
                          severityColor = "text-yellow-500";
                        } else if (p.findings.some(f => f.severity === "low")) {
                          topSeverity = "LOW";
                          severityColor = "text-cyber-light";
                        } else {
                          topSeverity = "INFO";
                          severityColor = "text-sky-400";
                        }
                      }

                      return (
                        <React.Fragment key={p.url}>
                          
                          {/* Main Row */}
                          <tr 
                            onClick={() => {
                              if (hasFailed) return;
                              setExpandedProjectUrl(isExpanded ? null : p.url);
                            }}
                            className={`border-b border-[#1f2833]/40 transition-colors select-none ${
                              hasFailed 
                                ? "opacity-60 cursor-not-allowed bg-red-950/5" 
                                : "cursor-pointer hover:bg-[#1f2833]/15"
                            } ${isExpanded ? "bg-[#1f2833]/10" : ""}`}
                          >
                            <td className="p-3.5 font-sans font-medium text-white truncate max-w-sm" title={p.url}>
                              {p.url}
                              {hasFailed && (
                                <span className="block font-mono text-[9px] text-cyber-red mt-0.5">
                                  Failed: {p.error || "Blocked Loopback/SSRF"}
                                </span>
                              )}
                            </td>
                            <td className="p-3.5 text-center">
                              <span className={`inline-block font-bold px-2 py-0.5 rounded text-[11px] ${
                                p.grade === "A" 
                                  ? "text-cyber-green bg-cyber-green/5 border border-cyber-green/20" 
                                  : p.grade === "B" 
                                  ? "text-cyber-light bg-cyber-light/5 border border-cyber-light/20"
                                  : p.grade === "C" || p.grade === "D"
                                  ? "text-cyber-orange bg-cyber-orange/5 border border-cyber-orange/20"
                                  : "text-cyber-red bg-cyber-red/5 border border-cyber-red/20"
                              }`}>
                                {p.grade || "N/A"}
                              </span>
                            </td>
                            <td className="p-3.5 text-center font-bold text-white">
                              {p.findingsCount}
                            </td>
                            <td className={`p-3.5 text-center font-bold ${severityColor}`}>
                              {topSeverity}
                            </td>
                            <td className="p-3.5 text-center text-cyber-gray/70 text-[10px]">
                              {p.platformDetected || "Generic/Other"}
                            </td>
                          </tr>

                          {/* Expanded Findings Details */}
                          {isExpanded && p.findings && (
                            <tr>
                              <td colSpan={5} className="bg-[#0b0c10]/80 border-b border-[#1f2833] p-5">
                                <div className="space-y-4 max-w-3xl">
                                  <div className="flex items-center justify-between border-b border-[#1f2833]/40 pb-2 mb-3">
                                    <span className="font-mono text-xs text-cyber-light uppercase tracking-wide">// Detailed Audit Logs</span>
                                    <span className="text-[10px] text-cyber-gray/50">{p.findings.length} findings discovered</span>
                                  </div>
                                  
                                  {p.findings.length === 0 ? (
                                    <div className="text-center py-4 text-cyber-green text-xs font-semibold">
                                      No security vulnerabilities discovered on this host.
                                    </div>
                                  ) : (
                                    <div className="space-y-3">
                                      {p.findings.map(finding => (
                                        <FindingCard 
                                          key={finding.id} 
                                          finding={finding} 
                                          onCopyPrompt={handleCopyPrompt}
                                          copiedId={copiedId}
                                        />
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}

                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* ERROR SCREEN */}
        {scanState === "error" && (
          <div className="w-full max-w-md px-4 py-16 flex flex-col items-center text-center">
            <div className="h-16 w-16 rounded-full bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center mb-6 glow-red">
              <AlertOctagon className="h-8 w-8 text-cyber-red" />
            </div>
            
            <h2 className="text-lg font-bold text-white tracking-tight">Audit Request Failed</h2>
            <p className="text-xs text-cyber-red font-mono bg-cyber-red/5 border border-cyber-red/20 px-3 py-2 rounded mt-3 max-w-full break-words">
              {errorMessage}
            </p>

            {/* Specific Batch URL SSRF/Validation Failures */}
            {batchValidationErrors.length > 0 && (
              <div className="w-full bg-[#0b0c10] border border-[#1f2833] rounded-lg p-3 text-left mt-4 max-h-40 overflow-y-auto font-mono text-[10px]">
                <div className="text-cyber-light font-bold mb-1.5 uppercase">// Invalid Batch URLs:</div>
                <div className="space-y-1">
                  {batchValidationErrors.map((errItem, idx) => (
                    <div key={idx} className="border-b border-[#1f2833]/40 pb-1 last:border-0">
                      <span className="text-white block font-medium truncate">{errItem.url}</span>
                      <span className="text-cyber-red block mt-0.5">Reason: {errItem.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <p className="text-xs text-cyber-gray/60 mt-4 max-w-xs leading-normal">
              Please make sure the target URLs are correct, public, and not pointing to local/private addresses.
            </p>
            <button
              onClick={() => {
                setBatchValidationErrors([]);
                setScanState("landing");
              }}
              className="mt-6 font-mono text-xs bg-[#1f2833] hover:bg-[#1f2833]/85 text-white py-2 px-5 rounded-lg border border-[#1f2833] transition-all cursor-pointer"
            >
              Return Home
            </button>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-[#1f2833]/40 bg-[#0b0c10]/95 py-6">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-[10px] font-mono text-cyber-gray/40">
          <span>&copy; {new Date().getFullYear()} NeuraauditAI. A product of NeuratantraAI. All scans are read-only and passive.</span>
          <div className="flex gap-4">
            <button 
              onClick={() => setShowPrivacyModal(true)} 
              className="hover:underline hover:text-cyber-light cursor-pointer select-none outline-none border-none bg-transparent font-mono text-[10px] text-cyber-gray/40"
            >
              Privacy Policy
            </button>
          </div>
        </div>
      </footer>
      {/* Privacy Policy Modal */}
      {showPrivacyModal && (
        <div className="fixed inset-0 z-[100] bg-[#0b0c10]/90 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b0c10] border border-[#1f2833] rounded-xl max-w-lg w-full max-h-[80vh] flex flex-col p-6 overflow-hidden relative shadow-2xl glow-teal">
            <div className="flex items-center justify-between border-b border-[#1f2833] pb-4 mb-4">
              <div className="flex items-center gap-2 text-cyber-light">
                <ShieldAlert className="h-5 w-5" />
                <h3 className="font-mono text-sm font-bold uppercase tracking-wider">Privacy Policy</h3>
              </div>
              <button 
                onClick={() => setShowPrivacyModal(false)} 
                className="text-cyber-gray hover:text-white font-mono text-xs cursor-pointer select-none border-none bg-transparent outline-none"
              >
                [ ESC / CLOSE ]
              </button>
            </div>
            
            <div className="overflow-y-auto space-y-4 text-cyber-gray/80 text-[11px] font-mono pr-2 leading-relaxed">
              <div>
                <h4 className="text-white text-xs font-bold uppercase mb-1">// 1. Overview</h4>
                <p>
                  NeuraauditAI is a security audit engine developed by NeuratantraAI. All scans conducted by NeuraauditAI are purely passive, read-only, and external. We do not download code bases, breach private access keys, or perform active penetration tests.
                </p>
              </div>
              
              <div>
                <h4 className="text-white text-xs font-bold uppercase mb-1">// 2. Scan Data Storage</h4>
                <p>
                  Audit results and configurations are stored securely inside our PostgreSQL database hosted on Supabase (with Row-Level Security enabled). Scan data is kept for up to 30 days to populate the scan history dashboard for users and is automatically pruned.
                </p>
              </div>
              
              <div>
                <h4 className="text-white text-xs font-bold uppercase mb-1">// 3. User Consent & Authorization</h4>
                <p>
                  By executing any audit on our platform, you explicitly represent that you have authorization and consent to check the destination target URL. You agree that NeuraauditAI is not liable for scans performed on unauthorized domains.
                </p>
              </div>
              
              <div>
                <h4 className="text-white text-xs font-bold uppercase mb-1">// 4. Artificial Intelligence Processing</h4>
                <p>
                  To generate natural language security explanations, scan findings are processed using Google Gemini models. No user account credentials, email addresses, or identifying client metadata are shared with third-party AI APIs during this query.
                </p>
              </div>
            </div>

            <div className="border-t border-[#1f2833] pt-4 mt-4 flex justify-end">
              <button 
                onClick={() => setShowPrivacyModal(false)}
                className="bg-cyber-light hover:bg-cyber-teal text-cyber-dark font-semibold font-mono text-xs px-5 py-2 rounded transition-all cursor-pointer border-none"
              >
                Acknowledge
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Subcomponent: Expandable Card for individual findings
function FindingCard({ finding, onCopyPrompt, copiedId }) {
  const [expanded, setExpanded] = useState(false);

  const severityStyles = {
    critical: { text: "text-cyber-red", bg: "bg-cyber-red/10", border: "border-cyber-red/30", label: "Critical" },
    high: { text: "text-[#f59e0b]", bg: "bg-[#f59e0b]/10", border: "border-[#f59e0b]/30", label: "High" },
    medium: { text: "text-yellow-500", bg: "bg-yellow-500/10", border: "border-yellow-500/20", label: "Medium" },
    low: { text: "text-cyber-light", bg: "bg-cyber-light/10", border: "border-cyber-light/20", label: "Low" },
    info: { text: "text-sky-400", bg: "bg-sky-400/10", border: "border-sky-400/20", label: "Info" }
  };

  const currentStyle = severityStyles[finding.severity] || severityStyles.info;

  const plainEnglishExplanations = {
    "ssl-invalid": "Your website's secure padlock is broken or expired. Browsers will show a giant red warning screen to users, which looks highly unprofessional and blocks traffic.",
    "ssl-expiring": "Your secure encryption certificate expires in a few days. You need to renew it soon to prevent browser warnings.",
    "http-no-redirect": "Users visiting 'http://' are not forced to the secure 'https://' version. This leaves them vulnerable to password eavesdropping on public Wi-Fi networks.",
    "header-missing-content-security-policy": "Your app does not restrict which domains it can load scripts from. This allows malicious hackers to inject bad scripts (Cross-Site Scripting or XSS) into your page.",
    "header-missing-x-frame-options": "Your site can be embedded inside invisible frames on other domains. Attackers can trick your users into clicking invisible buttons (Clickjacking).",
    "header-missing-x-content-type-options": "The browser is allowed to guess file types (mime-sniffing) which can cause it to run styling or image files as executable scripts.",
    "header-missing-strict-transport-security": "Your server does not instruct browsers to remember to use SSL. Users are susceptible to connection downgrade attacks on their first visit.",
    "header-missing-referrer-policy": "Your app doesn't control what referral data is sent to external links when users click out. This can leak private query parameters to third parties.",
    "exposed-supabase-service-role": "Your master database admin key (service_role) is exposed in your compiled script bundle. Anyone can extract this key and delete or steal your entire database, bypassing all tables rules!",
    "firebase-firestore-rls-bypass": "Your database collection is publicly readable on Firestore. Anyone can construct a simple query and extract your users' data without logging in.",
    "cors-wildcard-creds": "Your server API permits any origin (*) to read responses and accepts credentials. Malicious sites can make queries and read users' private session profiles.",
    "vulnerable-jquery": "Your app is loading an older version of jQuery that has well-documented security flaws. Hackers can exploit these flaws to run bad code in your users' browsers.",
    "idor-url-smell": "Your API uses guessable IDs (like /user/1). A user could change the number to 2 and read another user's profile if your backend lacks authorization controls.",
    "exposed-source-map": "Your application maps are exposed. Anyone can look at your original client-side source code, files layout, comments, and routes exactly as you wrote them on your computer.",
    "exposed-llm-system-prompt": "Your proprietary LLM system prompt is exposed in your compiled client code. Competitors can copy your prompt engineering, and attackers can read it to find prompt-injection vulnerabilities to manipulate your AI's behavior.",
    "graphql-introspection-enabled": "Your GraphQL endpoint has schema introspection enabled. Anyone can query your schema structure and retrieve the name of every database table, field, type, and relation, making it trivial to map your backend and craft malicious queries."
  };

  const getExplanation = (finding) => {
    if (plainEnglishExplanations[finding.id]) {
      return plainEnglishExplanations[finding.id];
    }
    if (finding.id.startsWith("supabase-rls-bypass")) {
      const tableName = finding.id.split("-").pop();
      return `Row-Level Security is bypassed on the '${tableName}' table. Anyone can send a request to your database and read, modify, or delete records from the '${tableName}' table without authenticating.`;
    }
    if (finding.id.startsWith("exposed-file-")) {
      const fileName = finding.id.replace("exposed-file-", "");
      return `Your configurations file '.${fileName}' is publicly downloadable. This leaks secret backend details, environment setups, and passwords directly to visitors.`;
    }
    if (finding.id.startsWith("cookie-no-")) {
      return `A cookie set by your site lacks security flags (Secure, HttpOnly, or SameSite). If an attacker intercepts your users' connection or runs scripts on the page, they can hijack their login session.`;
    }
    if (finding.id.startsWith("auth-cache-")) {
      return `Your authentication pages do not enforce cache prevention. If a user logs in on a public computer, the next user can click the browser back button and potentially see cached login states.`;
    }
    return finding.evidence || "No description available.";
  };

  const getFixPrompt = (finding) => {
    const title = finding.title;
    let fixText = "";

    if (finding.id.startsWith("supabase-rls-bypass")) {
      const tableName = finding.id.split("-").pop();
      fixText = `Fix this Supabase RLS issue in my project. The '${tableName}' table has RLS disabled or missing policies. Please write the SQL query or show me how to turn on Row-Level Security on the '${tableName}' table in the Supabase Dashboard, and configure standard SELECT policies so users can only read their own rows.`;
    } else if (finding.id === "exposed-supabase-service-role") {
      fixText = `I accidentally leaked my Supabase 'service_role' key in the client-side code of my React frontend. Please check my Supabase client initialization. I need to replace it with the public 'anon' key instead, and make sure the service_role key is deleted from my repository and client files immediately.`;
    } else if (finding.id === "exposed-llm-system-prompt") {
      fixText = `My LLM system prompt is hardcoded in my compiled frontend JavaScript bundle. Anyone can read it from the sources tab. Please help me refactor my app to store the system prompt securely on a backend server, and call the LLM completions endpoint via my own backend API rather than calling the LLM provider directly from the client.`;
    } else if (finding.id === "graphql-introspection-enabled") {
      fixText = `GraphQL Introspection is enabled on my backend endpoint. Anyone can query my GraphQL schema and extract all tables, fields, and queries. Please show me how to disable introspection in production in my GraphQL server settings.`;
    } else if (finding.id.startsWith("exposed-file-")) {
      const fileName = finding.id.replace("exposed-file-", "");
      fixText = `My configuration file '.${fileName}' is exposed to the public. Please configure my hosting server or root build to exclude '.${fileName}' files from the published folder, and check my .gitignore to ensure '.${fileName}' is not committed to git.`;
    } else if (finding.id.startsWith("header-missing-")) {
      const headerName = finding.id.replace("header-missing-", "");
      fixText = `My server is missing the '${headerName}' security header. Please show me how to configure this response header in my backend server configuration (or show me how to set it up in Vercel/Netlify configuration files like vercel.json or netlify.toml) to follow security best practices.`;
    } else if (finding.id === "vulnerable-jquery") {
      fixText = `My project is using a vulnerable version of jQuery. Please show me how to update the package dependencies to use the latest secure jQuery package (>= 3.5.0) and help me replace any deprecated code that might break.`;
    } else if (finding.id === "idor-url-smell") {
      fixText = `I have a potential IDOR vulnerability where endpoints expose raw sequential IDs in API paths. Please update my backend controller queries to check if the authenticated user has permission to read the requested object ID before returning it.`;
    } else {
      fixText = `Fix this security issue: "${title}" (${finding.evidence}). Let's write code to fix it properly following industry standards.`;
    }

    return `Hey Lovable/Claude, I ran a security scan and found an issue: "${title}". Here is the evidence: "${finding.evidence}".

How to fix:
${fixText}`;
  };

  const explanation = getExplanation(finding);
  const fixPrompt = (finding.aiExplanation && finding.aiExplanation.fixPrompt) || getFixPrompt(finding);
  const hasAi = !!finding.aiExplanation;
  const displayTitle = hasAi ? finding.aiExplanation.plainSummary : finding.title;

  return (
    <div className={`bg-[#1f2833]/10 border ${expanded ? "border-[#1f2833] glow-teal" : "border-[#1f2833]/50"} rounded-lg transition-all`}>
      <div 
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between p-4 cursor-pointer select-none"
      >
        <div className="flex flex-col sm:flex-row sm:items-start gap-2 sm:gap-3 flex-grow min-w-0">
          <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded shrink-0 ${currentStyle.bg} ${currentStyle.text} border ${currentStyle.border} mt-0.5`}>
            {currentStyle.label}
          </span>
          <div className="flex-grow min-w-0">
            <h3 className="text-sm font-semibold text-white hover:text-cyber-light transition-colors leading-snug break-words">
              {displayTitle}
            </h3>
            {hasAi && (
              <p className="text-[10px] text-cyber-gray/40 font-mono mt-0.5 tracking-normal uppercase">
                [TECHNICAL ISSUE: {finding.title}]
              </p>
            )}
          </div>
        </div>
        <span className="text-cyber-gray/30 text-xs font-mono ml-4 shrink-0">
          {expanded ? "[ HIDE ]" : "[ SHOW ]"}
        </span>
      </div>

      {expanded && (
        <div className="border-t border-[#1f2833]/40 p-4 space-y-4 text-xs">
          
          <div>
            <h4 className="font-mono text-cyber-light uppercase tracking-wider text-[10px] mb-1.5">// How this could be exploited</h4>
            <p className="text-cyber-gray leading-relaxed">
              {hasAi ? finding.aiExplanation.attackScenario : explanation}
            </p>
          </div>

          <div>
            <h4 className="font-mono text-cyber-light uppercase tracking-wider text-[10px] mb-1.5">// What you could lose</h4>
            <p className="text-cyber-gray leading-relaxed">
              {hasAi ? finding.aiExplanation.consequence : "Exposition of user credentials, database layout, or server environment secrets to malicious injection."}
            </p>
          </div>

          <div>
            <h4 className="font-mono text-cyber-light uppercase tracking-wider text-[10px] mb-1.5">// Technical Evidence</h4>
            <div className="bg-[#0b0c10] border border-[#1f2833] rounded p-3 font-mono text-[11px] text-red-400 break-words leading-relaxed">
              {finding.evidence}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="font-mono text-cyber-light uppercase tracking-wider text-[10px]">// Lovable / Claude Fix Prompt</h4>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onCopyPrompt(finding.id, fixPrompt);
                }}
                className="flex items-center gap-1 text-[10px] font-mono text-cyber-light hover:text-white transition-colors"
              >
                {copiedId === finding.id ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-cyber-green" /> Copied!
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" /> Copy Prompt
                  </>
                )}
              </button>
            </div>
            <div className="bg-[#0b0c10]/95 border border-[#1f2833] rounded p-3 font-mono text-[10px] text-cyber-gray/70 max-h-40 overflow-y-auto whitespace-pre-wrap select-all leading-normal">
              {fixPrompt}
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
