const axios = require("axios");
const dns = require("dns").promises;
const tls = require("tls");
const https = require("https");
const http = require("http");
const ipaddr = require("ipaddr.js");
const { URL } = require("url");

const USER_AGENT = "NeuraauditAI-Scanner/1.0 (+https://neuraauditai.app)";
const REQUEST_TIMEOUT = 30000; // 30 seconds

// Check if an IP address is in a restricted range (SSRF check)
function isSafeIp(ipString) {
  try {
    let addr = ipaddr.parse(ipString);

    // Get IPv4 address if it is IPv4-mapped IPv6 (::ffff:127.0.0.1 -> 127.0.0.1)
    if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) {
      addr = addr.toIPv4Address();
    }

    const range = addr.range();
    const unsafeRanges = [
      "loopback",
      "private",
      "linkLocal",
      "uniqueLocal",
      "unspecified",
      "broadcast",
    ];

    if (unsafeRanges.includes(range)) {
      return false;
    }

    // Explicit localhost protection for standard string checks
    if (ipString === "127.0.0.1" || ipString === "::1" || ipString === "0.0.0.0") {
      return false;
    }

    return true;
  } catch (e) {
    return false; // Treat unparseable IPs as unsafe
  }
}

// Resolves a hostname to its IP address and validates it
async function resolveAndValidateHost(hostname) {
  // Allow localhost in development/testing environments for running fixtures
  if (process.env.NODE_ENV !== "production" && (hostname.toLowerCase() === "localhost" || hostname === "127.0.0.1")) {
    return "127.0.0.1";
  }

  if (hostname.toLowerCase() === "localhost") {
    throw new Error("Access to localhost is blocked.");
  }

  try {
    const addresses = await dns.resolve(hostname).catch(async () => {
      const result = await dns.lookup(hostname);
      return [result.address];
    });

    if (!addresses || addresses.length === 0) {
      throw new Error(`Could not resolve hostname: ${hostname}`);
    }

    const ip = addresses[0];
    if (!isSafeIp(ip)) {
      throw new Error(`Access to private IP range blocked: ${ip}`);
    }

    return ip;
  } catch (err) {
    throw new Error(`SSRF Validation failed: ${err.message}`);
  }
}

// Custom request function with IP pinning and manual redirect tracking
async function fetchWithSsrfCheck(targetUrl, method = "GET", headers = {}, data = null) {
  let currentUrl = targetUrl;
  let redirectsCount = 0;
  const maxRedirects = 3;

  while (redirectsCount <= maxRedirects) {
    const parsedUrl = new URL(currentUrl);
    const hostname = parsedUrl.hostname;

    // 1. Resolve host and perform SSRF validation
    const resolvedIp = await resolveAndValidateHost(hostname);

    // 2. Perform IP Pinning
    const isHttps = parsedUrl.protocol === "https:";
    const port = parsedUrl.port || (isHttps ? 443 : 80);

    // Rewrite URL to use the resolved IP address directly
    const portSuffix = parsedUrl.port ? `:${parsedUrl.port}` : "";
    const pinnedUrl = `${parsedUrl.protocol}//${resolvedIp}${portSuffix}${parsedUrl.pathname}${parsedUrl.search}`;

    const requestHeaders = {
      ...headers,
      "Host": hostname,
      "User-Agent": USER_AGENT,
    };

    const agentOptions = {
      keepAlive: false,
    };

    if (isHttps) {
      agentOptions.servername = hostname; // Inject SNI for SSL validation
    }

    const agent = isHttps
      ? new https.Agent(agentOptions)
      : new http.Agent(agentOptions);

    try {
      const config = {
        method,
        url: pinnedUrl,
        headers: requestHeaders,
        timeout: REQUEST_TIMEOUT,
        maxRedirects: 0, // Enforce manual redirect handling
        validateStatus: (status) => true, // Handle responses manually
        [isHttps ? "httpsAgent" : "httpAgent"]: agent,
      };

      if (data) {
        config.data = data;
      }

      const response = await axios(config);

      // Handle Redirects
      if (response.status >= 300 && response.status < 400 && response.headers.location) {
        redirectsCount++;
        let redirectLocation = response.headers.location;

        // Convert relative redirect to absolute URL
        if (!redirectLocation.startsWith("http:") && !redirectLocation.startsWith("https:")) {
          redirectLocation = new URL(redirectLocation, currentUrl).href;
        }

        currentUrl = redirectLocation;
        continue;
      }

      return response;
    } catch (err) {
      throw new Error(`Outbound connection error: ${err.message}`);
    }
  }

  throw new Error("Max redirects limit exceeded.");
}

// Checks if RLS is bypassed on a Supabase table
async function checkSupabaseRls(projectUrl, anonKey, table) {
  try {
    const tableUrl = `${projectUrl}/rest/v1/${table}?limit=1`;
    const response = await fetchWithSsrfCheck(tableUrl, "GET", {
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
    });

    // If 200 OK, it means we can read table records without authentication => RLS bypassed!
    if (response.status === 200) {
      return {
        bypassed: true,
        dataLength: Array.isArray(response.data) ? response.data.length : 0,
        sample: response.data,
      };
    }
    return { bypassed: false };
  } catch (err) {
    return { bypassed: false, error: err.message };
  }
}

// Checks if Firebase Firestore collection is readable publicly
async function checkFirestoreRls(projectId, collection = "users") {
  try {
    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?pageSize=1`;
    const response = await fetchWithSsrfCheck(firestoreUrl, "GET");

    if (response.status === 200) {
      return { bypassed: true, sample: response.data };
    }
    return { bypassed: false };
  } catch (e) {
    return { bypassed: false };
  }
}

// Checks SSL Expiry and validity
function checkSsl(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      443,
      hostname,
      { servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({ valid: false, error: "No certificate returned" });
        }

        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        const expired = daysRemaining <= 0;

        resolve({
          valid: !expired,
          issuer: cert.issuer.O || cert.issuer.CN,
          validTo: cert.valid_to,
          daysRemaining,
        });
      }
    );

    socket.on("error", (err) => {
      resolve({ valid: false, error: err.message });
    });

    // Enforce connection timeout
    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ valid: false, error: "SSL connection timed out" });
    });
  });
}

// Main Scan Logic
async function runScan(targetUrl) {
  const startTime = Date.now();
  const findings = [];
  let parsedUrl;

  try {
    parsedUrl = new URL(targetUrl);
  } catch (e) {
    throw new Error("Invalid URL provided.");
  }

  const hostname = parsedUrl.hostname;

  // 1. SSL/TLS Verification
  if (parsedUrl.protocol === "https:") {
    const sslInfo = await checkSsl(hostname);
    if (!sslInfo.valid) {
      findings.push({
        id: "ssl-invalid",
        category: "Network",
        title: "Invalid SSL/TLS Certificate",
        severity: "critical",
        evidence: `Error details: ${sslInfo.error || "Expired"}`,
        rawTechnicalDetail: JSON.stringify(sslInfo),
      });
    } else if (sslInfo.daysRemaining < 15) {
      findings.push({
        id: "ssl-expiring",
        category: "Network",
        title: "SSL/TLS Certificate Expiring Soon",
        severity: "medium",
        evidence: `Certificate expires in ${sslInfo.daysRemaining} days on ${sslInfo.validTo}`,
        rawTechnicalDetail: JSON.stringify(sslInfo),
      });
    }
  }

  // 2. HTTP to HTTPS redirect check
  if (parsedUrl.protocol === "http:") {
    try {
      const httpResponse = await fetchWithSsrfCheck(targetUrl, "GET");
      const redirectedUrl = httpResponse.request?.res?.responseUrl || "";
      if (!redirectedUrl.startsWith("https:")) {
        findings.push({
          id: "http-no-redirect",
          category: "Transport",
          title: "HTTP to HTTPS redirect not enforced",
          severity: "high",
          evidence: `Requested http version and was not redirected to https`,
          rawTechnicalDetail: `Status: ${httpResponse.status}`,
        });
      }
    } catch (e) {
      // Ignore HTTP redirect errors if site is HTTPS-only anyway
    }
  }

  // 3. Fetch home page and search headers & HTML
  let homepageHtml = "";
  let responseHeaders = {};
  let mainUrlToFetch = parsedUrl.href;

  try {
    const res = await fetchWithSsrfCheck(mainUrlToFetch);
    homepageHtml = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    responseHeaders = res.headers;
  } catch (err) {
    throw new Error(`Failed to fetch main page: ${err.message}`);
  }

  // Check Security Headers
  const securityHeaders = [
    { name: "content-security-policy", title: "Missing Content-Security-Policy header", severity: "high" },
    { name: "x-frame-options", title: "Missing X-Frame-Options (Clickjacking vulnerability)", severity: "medium" },
    { name: "x-content-type-options", title: "Missing X-Content-Type-Options header", severity: "low" },
    { name: "strict-transport-security", title: "Missing Strict-Transport-Security (HSTS) header", severity: "high" },
    { name: "referrer-policy", title: "Missing Referrer-Policy header", severity: "low" },
  ];

  securityHeaders.forEach((sh) => {
    if (!responseHeaders[sh.name]) {
      findings.push({
        id: `header-missing-${sh.name}`,
        category: "Network",
        title: sh.title,
        severity: sh.severity,
        evidence: `Header '${sh.name}' is missing in HTTP response headers.`,
        rawTechnicalDetail: JSON.stringify(responseHeaders),
      });
    }
  });

  // Check Cookies
  const setCookieHeaders = responseHeaders["set-cookie"];
  if (setCookieHeaders) {
    const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    cookies.forEach((cookie) => {
      const name = cookie.split("=")[0];
      const isSecure = /secure/i.test(cookie);
      const isHttpOnly = /httponly/i.test(cookie);
      const hasSameSite = /samesite/i.test(cookie);

      if (!isSecure) {
        findings.push({
          id: `cookie-no-secure-${name}`,
          category: "Application",
          title: `Cookie '${name}' missing Secure attribute`,
          severity: "medium",
          evidence: cookie,
          rawTechnicalDetail: cookie,
        });
      }
      if (!isHttpOnly) {
        findings.push({
          id: `cookie-no-httponly-${name}`,
          category: "Application",
          title: `Cookie '${name}' missing HttpOnly attribute`,
          severity: "high",
          evidence: cookie,
          rawTechnicalDetail: cookie,
        });
      }
      if (!hasSameSite) {
        findings.push({
          id: `cookie-no-samesite-${name}`,
          category: "Application",
          title: `Cookie '${name}' missing SameSite attribute`,
          severity: "low",
          evidence: cookie,
          rawTechnicalDetail: cookie,
        });
      }
    });
  }

  // 4. Exposed static files checks (GET env, git/config etc.)
  const filesToCheck = [
    { path: "/.env", title: "Exposed Environment Variables (.env)", severity: "critical" },
    { path: "/.env.local", title: "Exposed Local Environment Variables (.env.local)", severity: "critical" },
    { path: "/.git/config", title: "Exposed Git Configuration (.git/config)", severity: "critical" },
    { path: "/.git/HEAD", title: "Exposed Git HEAD Reference (.git/HEAD)", severity: "high" },
  ];

  for (const file of filesToCheck) {
    try {
      const fileUrl = `${parsedUrl.origin}${file.path}`;
      const res = await fetchWithSsrfCheck(fileUrl);
      // Valid file exposes shouldn't be HTML fallback indices (often returning 200 with index.html in SPAs)
      const dataStr = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
      const isHtml = dataStr.trim().startsWith("<!DOCTYPE") || dataStr.trim().startsWith("<html");

      if (res.status === 200 && !isHtml && dataStr.length > 5) {
        findings.push({
          id: `exposed-file-${file.path.replace(/\//g, "")}`,
          category: "Secrets",
          title: file.title,
          severity: file.severity,
          evidence: `Accessed ${fileUrl} successfully. Contents start with: "${dataStr.slice(0, 100).replace(/\n/g, " ")}"`,
          rawTechnicalDetail: dataStr.slice(0, 1000),
        });
      }
    } catch (e) {
      // Endpoint doesn't exist or errored, which is secure
    }
  }

  // 5. JavaScript files parsing & secrets detection
  const jsRegex = /<script[^>]+src=["']([^"']+\.js)/gi;
  const scriptUrls = [];
  let match;
  while ((match = jsRegex.exec(homepageHtml)) !== null) {
    let scriptUrl = match[1];
    if (scriptUrl.startsWith("//")) {
      scriptUrl = parsedUrl.protocol + scriptUrl;
    } else if (scriptUrl.startsWith("/")) {
      scriptUrl = parsedUrl.origin + scriptUrl;
    } else if (!scriptUrl.startsWith("http")) {
      scriptUrl = parsedUrl.origin + "/" + scriptUrl;
    }
    scriptUrls.push(scriptUrl);
  }

  // Check if main script is exposed
  let combinedJsContent = "";
  for (const scriptUrl of scriptUrls.slice(0, 5)) { // Limit to top 5 scripts
    try {
      const res = await fetchWithSsrfCheck(scriptUrl);
      if (res.status === 200 && typeof res.data === "string") {
        combinedJsContent += res.data + "\n";
      }
    } catch (e) {
      // Ignore script errors
    }
  }

  // Check Source Maps
  for (const scriptUrl of scriptUrls.slice(0, 3)) {
    try {
      const mapUrl = `${scriptUrl}.map`;
      const res = await fetchWithSsrfCheck(mapUrl);
      if (res.status === 200 && (typeof res.data === "string" || typeof res.data === "object")) {
        findings.push({
          id: "exposed-source-map",
          category: "Application",
          title: "Source Maps Exposed (.map files)",
          severity: "medium",
          evidence: `Source map accessible at: ${mapUrl}`,
          rawTechnicalDetail: `Vulnerability allows reconstruction of original source code.`,
        });
        break; // Only need to flag once
      }
    } catch (e) {}
  }

  // Secrets Regex Patterns
  const SECRET_PATTERNS = [
    { id: "key-openai", title: "Exposed OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{48}/g, severity: "critical" },
    { id: "key-openai-proj", title: "Exposed OpenAI Project Key", pattern: /sk-proj-[a-zA-Z0-9_-]{40,}/g, severity: "critical" },
    { id: "key-anthropic", title: "Exposed Anthropic API Key", pattern: /sk-ant-[a-zA-Z0-9_-]{40,}/g, severity: "critical" },
    { id: "key-gemini", title: "Exposed Google/Gemini API Key", pattern: /AIzaSy[a-zA-Z0-9_-]{33}/g, severity: "critical" },
    { id: "key-stripe-secret", title: "Exposed Stripe Secret Key", pattern: /sk_live_[a-zA-Z0-9]{24,}/g, severity: "critical" },
    { id: "key-stripe-pub", title: "Stripe Publishable Key Detected", pattern: /pk_live_[a-zA-Z0-9]{24,}/g, severity: "info" },
    { id: "key-aws-id", title: "Exposed AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
    { id: "key-sendgrid", title: "Exposed SendGrid API Key", pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: "critical" },
    { id: "key-mapbox", title: "Exposed Mapbox Access Token", pattern: /pk\.eyJ1[a-zA-Z0-9._-]{50,}/g, severity: "critical" },
  ];

  SECRET_PATTERNS.forEach((sp) => {
    let match;
    const contentToScan = homepageHtml + "\n" + combinedJsContent;
    const seen = new Set();
    while ((match = sp.pattern.exec(contentToScan)) !== null) {
      const matchVal = match[0];
      if (!seen.has(matchVal)) {
        seen.add(matchVal);
        findings.push({
          id: sp.id,
          category: "Secrets",
          title: sp.title,
          severity: sp.severity,
          evidence: `Found key pattern matching: ...${matchVal.slice(-10)}`,
          rawTechnicalDetail: `Matches regex pattern.`,
        });
      }
    }
  });

  // Supabase RLS Leak Check
  // supabase url pattern: https://[project].supabase.co
  const supabaseUrlRegex = process.env.NODE_ENV !== "production"
    ? /(https:\/\/[a-z0-9\-]+\.supabase\.co|http:\/\/localhost:3000\/api\/test-fixture)/gi
    : /https:\/\/[a-z0-9\-]+\.supabase\.co/gi;
  const anonKeyRegex = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;

  const contentToScan = homepageHtml + "\n" + combinedJsContent;
  const supabaseUrls = [...new Set(contentToScan.match(supabaseUrlRegex))];
  const jwts = [...new Set(contentToScan.match(anonKeyRegex))];

  let supabaseAnonKey = null;
  let supabaseServiceRoleKey = null;

  // Find Supabase Keys
  jwts.forEach((jwt) => {
    try {
      const parts = jwt.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64").toString("utf-8"));
        if (payload.role === "anon") {
          supabaseAnonKey = jwt;
        } else if (payload.role === "service_role") {
          supabaseServiceRoleKey = jwt;
        }
      }
    } catch (e) {}
  });

  if (supabaseServiceRoleKey) {
    findings.push({
      id: "exposed-supabase-service-role",
      category: "Secrets",
      title: "Exposed Supabase service_role Key",
      severity: "critical",
      evidence: `Found JWT payload with role: 'service_role'. This bypasses all security checks!`,
      rawTechnicalDetail: `Supabase service_role key found in public bundle.`,
    });
  }

  // If we found a supabase project + anon key, run a passive check on common tables
  if (supabaseUrls.length > 0 && supabaseAnonKey) {
    const projUrl = supabaseUrls[0];
    // Common tables in typical student projects
    const commonTables = ["users", "profiles", "orders", "tasks", "messages", "settings"];
    
    // Extract custom table names dynamically from JS bundle code
    const tableRegex = /\.from\(['"]([a-zA-Z0-9_-]+)['"]\)/g;
    const extractedTables = [];
    let tableMatch;
    tableRegex.lastIndex = 0;
    while ((tableMatch = tableRegex.exec(contentToScan)) !== null) {
      extractedTables.push(tableMatch[1]);
    }
    
    const tablesToProbe = [...new Set([...commonTables, ...extractedTables])];

    for (const table of tablesToProbe) {
      const rlsResult = await checkSupabaseRls(projUrl, supabaseAnonKey, table);
      if (rlsResult.bypassed) {
        findings.push({
          id: `supabase-rls-bypass-${table}`,
          category: "Database",
          title: `Supabase Row-Level Security (RLS) Bypassed on '${table}' table`,
          severity: "critical",
          evidence: `Able to read data from ${projUrl}/rest/v1/${table} using public anon key.`,
          rawTechnicalDetail: `Bypass detected. Record sample preview: ${JSON.stringify(rlsResult.sample).slice(0, 200)}`,
        });
      }
    }
  }

  // Firebase project check
  const firebaseProjRegex = /"projectId"\s*:\s*["']([^"']+)["']/i;
  const firebaseMatch = firebaseProjRegex.exec(contentToScan);
  if (firebaseMatch) {
    const projectId = firebaseMatch[1];
    const firestoreResult = await checkFirestoreRls(projectId, "users");
    if (firestoreResult.bypassed) {
      findings.push({
        id: "firebase-firestore-rls-bypass",
        category: "Database",
        title: "Firebase Firestore Public Read Allowed (Missing RLS)",
        severity: "critical",
        evidence: `Able to query Firestore REST API for collection 'users' without credentials.`,
        rawTechnicalDetail: `URL: https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users`,
      });
    }
  }

  // 6. CORS check
  // Scan JS files for custom endpoints and verify headers on them (if possible)
  const apiEndpointRegex = /(https?:\/\/[^\s"'`]+)/g;
  const potentialEndpoints = [];
  let epMatch;
  while ((epMatch = apiEndpointRegex.exec(contentToScan)) !== null) {
    const urlStr = epMatch[1];
    if (urlStr.includes("/api/") || urlStr.includes("/v1/")) {
      potentialEndpoints.push(urlStr);
    }
  }

  const uniqueEndpoints = [...new Set(potentialEndpoints)].slice(0, 2);
  for (const ep of uniqueEndpoints) {
    try {
      const res = await fetchWithSsrfCheck(ep, "OPTIONS", {
        "Origin": "https://attacker-domain-malicious.com",
        "Access-Control-Request-Method": "GET",
      });

      const corsOrigin = res.headers["access-control-allow-origin"];
      const corsCreds = res.headers["access-control-allow-credentials"];

      if (corsOrigin === "*" && corsCreds === "true") {
        findings.push({
          id: "cors-wildcard-creds",
          category: "Network",
          title: "Dangerous CORS Configuration: Wildcard + Credentials",
          severity: "high",
          evidence: `Endpoint: ${ep} allows Origin: * combined with Access-Control-Allow-Credentials: true`,
          rawTechnicalDetail: `Allows cross-origin state reading.`,
        });
      }
    } catch (e) {}
  }

  // 7. Auth Page Cache Control
  const authPaths = ["/login", "/signup", "/reset-password"];
  for (const ap of authPaths) {
    try {
      const authUrl = `${parsedUrl.origin}${ap}`;
      const res = await fetchWithSsrfCheck(authUrl);
      const cacheControl = res.headers["cache-control"] || "";
      if (res.status === 200 && !cacheControl.includes("no-store")) {
        findings.push({
          id: `auth-cache-control-${ap.replace("/", "")}`,
          category: "Application",
          title: `Auth Page '${ap}' Missing Cache-Control: no-store`,
          severity: "medium",
          evidence: `Response headers at ${authUrl}: Cache-Control is "${cacheControl}"`,
          rawTechnicalDetail: `Allows sensitive credentials/tokens to stay in browser history cache.`,
        });
      }
    } catch (e) {}
  }

  // 8. Fingerprint platform
  let platformDetected = "Generic/Other";
  const serverHeader = responseHeaders["server"] || "";
  const viaHeader = responseHeaders["via"] || "";
  const xPoweredBy = responseHeaders["x-powered-by"] || "";

  if (serverHeader.includes("Vercel") || responseHeaders["x-vercel-id"]) {
    platformDetected = "Vercel";
  } else if (serverHeader.includes("Netlify") || responseHeaders["x-nf-request-id"]) {
    platformDetected = "Netlify";
  } else if (xPoweredBy.includes("Render") || viaHeader.includes("render")) {
    platformDetected = "Render";
  } else if (serverHeader.includes("cloudflare")) {
    platformDetected = "Cloudflare Pages/Workers";
  }

  // 9. Dependency Vulnerabilities
  // Look for React/jQuery versions in code
  const jqueryVersionRegex = /jQuery\s*v?([0-9\.]+)/i;
  const jqMatch = jqueryVersionRegex.exec(contentToScan);
  if (jqMatch) {
    const version = jqMatch[1];
    // Bundle standard vulnerable jQuery ranges
    if (version.startsWith("1.") || version.startsWith("2.") || (version.startsWith("3.") && parseInt(version.split(".")[1]) < 5)) {
      findings.push({
        id: "vulnerable-jquery",
        category: "Dependencies",
        title: `Vulnerable jQuery Version Detected (${version})`,
        severity: "medium",
        evidence: `Detected jQuery version v${version} which has known vulnerabilities (CVE-2020-11022, CVE-2020-11023).`,
        rawTechnicalDetail: `jQuery v${version} loaded. Recommended: upgrade to >= 3.5.0.`,
      });
    }
  }

  // 10. IDOR Smell Test
  const idorRegex = /\/api\/v[0-9]\/[a-z\-]+\/[0-9]+/gi;
  const hasIdorSmell = idorRegex.test(contentToScan);
  if (hasIdorSmell) {
    findings.push({
      id: "idor-url-smell",
      category: "Application",
      title: "Potential IDOR Vulnerability Pattern",
      severity: "medium",
      evidence: `Found URL paths containing sequential, numeric resource identifiers.`,
      rawTechnicalDetail: `Sequential API routing patterns detected. Ensure objects are validated before access.`,
    });
  }

  // 11. AI/LLM Exposure Check: LLM System Prompt Leakage
  const llmHosts = ["api.openai.com", "generativelanguage.googleapis.com", "api.anthropic.com"];
  const scaffolding = [
    "you are a", "you are an ai", "your role is", "system:", 
    "you must always", "respond only in", "do not reveal", "instructions:"
  ];

  // Regex to match string literals (single quotes, double quotes, backticks)
  const stringRegex = /(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)/g;
  let strMatch;
  stringRegex.lastIndex = 0;

  while ((strMatch = stringRegex.exec(contentToScan)) !== null) {
    const matchedString = strMatch[1] || strMatch[2] || strMatch[3] || "";
    const matchLength = matchedString.length;

    if (matchLength > 150) {
      const lowerStr = matchedString.toLowerCase();
      const hasScaffold = scaffolding.some(phrase => lowerStr.includes(phrase));

      if (hasScaffold) {
        const matchStart = strMatch.index;
        const matchEnd = matchStart + strMatch[0].length;

        // Search window: check 1000 characters before and after the matched string
        const windowStart = Math.max(0, matchStart - 1000);
        const windowEnd = Math.min(contentToScan.length, matchEnd + 1000);
        const searchWindow = contentToScan.substring(windowStart, windowEnd);

        const hasLlmHostNearby = llmHosts.some(host => searchWindow.includes(host));

        if (hasLlmHostNearby) {
          findings.push({
            id: "exposed-llm-system-prompt",
            category: "AI_LLM",
            title: "LLM System Prompt Exposed in Client Bundle",
            severity: "high",
            evidence: `Exposed prompt: "${matchedString.substring(0, 100)}..."`,
            rawTechnicalDetail: `Exposed system prompt literal found within 1000 characters of an LLM API hostname (${llmHosts.find(host => searchWindow.includes(host))}).`,
          });
          break; // Flag once
        }
      }
    }
  }

  // 12. AI/LLM Exposure Check: GraphQL Introspection
  const graphqlCandidates = new Set();
  const targetParsed = new URL(targetUrl);
  const targetOrigin = targetParsed.origin;
  
  graphqlCandidates.add(`${targetOrigin}/graphql`);
  graphqlCandidates.add(`${targetOrigin}/api/graphql`);
  graphqlCandidates.add(`${targetOrigin}/v1/graphql`);

  // Parse bundle for same-origin GraphQL endpoints
  const graphqlUrlRegex = /https?:\/\/[^\s"'`]+?(?:graphql|api\/graphql|v1\/graphql)/gi;
  let gqlUrlMatch;
  graphqlUrlRegex.lastIndex = 0;
  while ((gqlUrlMatch = graphqlUrlRegex.exec(contentToScan)) !== null) {
    const urlStr = gqlUrlMatch[0];
    try {
      const parsedGqlUrl = new URL(urlStr);
      if (parsedGqlUrl.origin === targetOrigin) {
        graphqlCandidates.add(parsedGqlUrl.origin + parsedGqlUrl.pathname + parsedGqlUrl.search);
      }
    } catch (e) {}
  }

  // Cap candidates to max 3
  const finalGqlCandidates = [...graphqlCandidates].slice(0, 3);

  for (const gqlUrl of finalGqlCandidates) {
    try {
      const response = await fetchWithSsrfCheck(
        gqlUrl,
        "POST",
        { "Content-Type": "application/json" },
        { query: "{ __schema { types { name } } }" }
      );

      if (response.status === 200 && response.data && response.data.data && response.data.data.__schema && Array.isArray(response.data.data.__schema.types)) {
        findings.push({
          id: "graphql-introspection-enabled",
          category: "AI_LLM",
          title: "GraphQL Introspection Enabled",
          severity: "high",
          evidence: `Introspection query succeeded at: ${gqlUrl}`,
          rawTechnicalDetail: `GraphQL endpoint allows schema introspection. Exposed ${response.data.data.__schema.types.length} schema types.`,
        });
        break; // Flag once
      }
    } catch (err) {
      // Ignore errors
    }
  }

  const scanDurationMs = Date.now() - startTime;

  return {
    url: targetUrl,
    scannedAt: new Date().toISOString(),
    findings,
    platformDetected,
    scanDurationMs,
  };
}

module.exports = {
  runScan,
  isSafeIp,
  resolveAndValidateHost,
  fetchWithSsrfCheck,
  checkSupabaseRls,
};
