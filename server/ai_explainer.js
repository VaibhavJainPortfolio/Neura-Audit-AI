const axios = require("axios");
const db = require("./db");

// Static fallback explanations for every possible finding ID
const STATIC_FALLBACKS = {
  "ssl-invalid": {
    plainSummary: "Your website's security certificate is invalid or broken.",
    attackScenario: "An attacker positions themselves on the same local Wi-Fi network as your user. Since the SSL certificate is invalid, the browser does not encrypt the traffic. The attacker intercepts the connection, displays a fake login page, and steals the user's password.",
    consequence: "Users will see a scary browser warning blocking access, causing complete loss of user trust and exposing session data to snooping.",
    fixPrompt: "My SSL certificate is invalid. Please show me how to generate and configure a valid, auto-renewing Let's Encrypt SSL certificate for my web server."
  },
  "ssl-expiring": {
    plainSummary: "Your security certificate is about to expire.",
    attackScenario: "In a few days, your website's SSL certificate will expire. When a student attempts to log in to submit an assignment, their browser will block the page and show an SSL expiration warning, preventing them from accessing your services.",
    consequence: "Immediate downtime and loss of service access for all users once the certificate expires.",
    fixPrompt: "My SSL certificate is expiring soon. Please help me renew it automatically using certbot or my hosting provider settings."
  },
  "http-no-redirect": {
    plainSummary: "Your site allows insecure HTTP connections without redirecting to HTTPS.",
    attackScenario: "A student logs in to your portal while connected to an unencrypted public library Wi-Fi network. Because your site doesn't force HTTPS, the login request is sent in cleartext. A malicious user sniffing packets on the same Wi-Fi intercepts their password.",
    consequence: "Exposure of user login credentials and session tokens to passive network interception.",
    fixPrompt: "Show me how to configure an automatic HTTP-to-HTTPS redirect on my web server or hosting platform."
  },
  "header-missing-content-security-policy": {
    plainSummary: "Your website lacks a Content Security Policy (CSP) header.",
    attackScenario: "An attacker finds an input field on your website that doesn't sanitize data. They inject a malicious script. Because there is no Content Security Policy to restrict script sources, the browser runs the script, which silently steals the session cookies of every visiting user.",
    consequence: "High risk of Cross-Site Scripting (XSS) attacks leading to user session hijacking and page defacement.",
    fixPrompt: "Please show me how to add a secure Content-Security-Policy header to my web application that permits scripts only from trusted sources."
  },
  "header-missing-x-frame-options": {
    plainSummary: "Your website can be embedded in other websites via frames.",
    attackScenario: "An attacker creates a malicious webpage that embeds your portal in an invisible iframe. They place a fake 'Free Gift' button directly over your portal's 'Delete Account' button. A logged-in user visits the malicious page, clicks the gift button, and unintentionally deletes their account.",
    consequence: "Risk of Clickjacking attacks where users are tricked into performing unintended actions.",
    fixPrompt: "Please show me how to configure the 'X-Frame-Options: DENY' or 'SAMEORIGIN' header in my web server."
  },
  "header-missing-x-content-type-options": {
    plainSummary: "Your server does not prevent browsers from guessing file types.",
    attackScenario: "An attacker uploads a text file containing malicious JavaScript, disguised as an image. Because your server does not send the X-Content-Type-Options: nosniff header, a victim's browser attempts to guess the file type and executes the malicious JavaScript in the victim's session.",
    consequence: "Risk of MIME-sniffing attacks leading to cross-site scripting vulnerabilities.",
    fixPrompt: "Show me how to set the 'X-Content-Type-Options: nosniff' header on my backend responses."
  },
  "header-missing-strict-transport-security": {
    plainSummary: "Your website does not instruct browsers to enforce HTTPS.",
    attackScenario: "A user types your website's URL into their browser address bar without specifying 'https://'. An attacker on the same local network intercepts the initial HTTP request and forwards it to a fake clone of your site. Because HSTS is missing, the browser does not automatically upgrade the connection to HTTPS.",
    consequence: "Vulnerability to SSL Strip connection downgrade attacks.",
    fixPrompt: "Show me how to configure the 'Strict-Transport-Security' (HSTS) header on my server with max-age."
  },
  "header-missing-referrer-policy": {
    plainSummary: "Your website does not control referrer information sent to external links.",
    attackScenario: "A user clicks an external link on your private dashboard. Because no Referrer Policy is set, the browser includes the full URL of your private dashboard—which contains a sensitive session token in the query parameters—in the 'Referer' header sent to the external site owner.",
    consequence: "Minor exposure of sensitive URL paths or tokens to external websites when navigating away.",
    fixPrompt: "Show me how to add a 'Referrer-Policy: strict-origin-when-cross-origin' header to my server."
  },
  "exposed-supabase-service-role": {
    plainSummary: "Your database administrative key is exposed to the public.",
    attackScenario: "An attacker inspects your compiled React JS bundle in their browser's developer tools. They find the hardcoded Supabase 'service_role' key. Using this key, the attacker makes direct API requests to your database, completely bypassing Row-Level Security (RLS) to download your entire user table and delete all tables.",
    consequence: "Complete compromise of all database records, leading to a catastrophic data breach and permanent data loss.",
    fixPrompt: "I leaked my Supabase service_role key in my client code. Help me remove it and move all admin queries to secure backend endpoints."
  },
  "firebase-firestore-rls-bypass": {
    plainSummary: "Your Firebase database rules allow anyone to read your data.",
    attackScenario: "An attacker extracts your Firebase project configurations from the source code. They open their terminal and run a simple curl command against the Firestore REST API. Because your rules are open, the database returns all user documents and private files without requiring credentials.",
    consequence: "Unauthorized access and theft of private user records, causing severe privacy violations.",
    fixPrompt: "My Firestore database is readable by anyone. Show me how to write secure Firestore security rules requiring user authentication."
  },
  "cors-wildcard-creds": {
    plainSummary: "Your API permits any external site to read user data with credentials.",
    attackScenario: "A user logged into your portal visits a malicious site. The malicious site runs a background script that sends a fetch request to your API. Because your API uses a wildcard CORS policy with credentials allowed, the browser sends the session cookie and lets the malicious site read the user's private data.",
    consequence: "Exposure of user sessions to cross-origin data theft by arbitrary external sites.",
    fixPrompt: "Show me how to restrict CORS allowed origins to my specific domain instead of using a wildcard when credentials are sent."
  },
  "vulnerable-jquery": {
    plainSummary: "Your app is loading an outdated, vulnerable version of jQuery.",
    attackScenario: "An attacker crafts a URL containing a malicious query parameter. When a victim clicks this link, the outdated version of jQuery attempts to parse the query parameter as HTML, executing the attacker's script. This lets the attacker steal the victim's session tokens.",
    consequence: "Known vulnerabilities in third-party libraries leave your portal open to cross-site scripting attacks.",
    fixPrompt: "Help me update my jQuery package to version >= 3.5.0 and replace any deprecated API calls."
  },
  "idor-url-smell": {
    plainSummary: "Your API endpoints use guessable, sequential numbers to identify resources.",
    attackScenario: "An attacker logs in and sees their profile URL is '/api/v1/user/101'. They guess that user 102 exists. They change the URL to '/api/v1/user/102'. Because the backend lacks authorization checks and uses simple numbers, it returns the private details of user 102.",
    consequence: "Unauthorized access to other users' accounts and documents by simply guessing numeric IDs.",
    fixPrompt: "Help me add authorization checks to my API routes to ensure users can only access resources belonging to them."
  },
  "exposed-source-map": {
    plainSummary: "Your original frontend source code is viewable by anyone.",
    attackScenario: "An attacker opens the Chrome DevTools 'Sources' tab on your live site. Because you deployed source maps (.js.map), Chrome reconstructs your original React source files, comments, and internal folders exactly as they exist on your computer, letting the attacker search for keys and private endpoints.",
    consequence: "Exposes your original source code and folders structure, simplifying the discovery of backend flaws and secrets.",
    fixPrompt: "Help me disable source maps generation in my Vite or webpack build configuration for production deployments."
  },
  "exposed-llm-system-prompt": {
    plainSummary: "Your AI's system instructions are visible in the client bundle.",
    attackScenario: "An attacker opens your compiled JavaScript code and searches for prompt instructions. They copy your proprietary prompt engineering templates. Furthermore, knowing your exact system instructions, they craft a prompt injection attack that easily bypasses your AI's guardrails.",
    consequence: "Theft of proprietary prompt engineering work, and increased vulnerability to AI jailbreaking and prompt injection.",
    fixPrompt: "My system prompt is hardcoded in the client bundle. Show me how to set up a secure proxy server that appends the system prompt on the backend."
  },
  "graphql-introspection-enabled": {
    plainSummary: "Your database schema can be queried by anyone.",
    attackScenario: "An attacker discovers your GraphQL endpoint. They send a POST query requesting '__schema'. The server returns the entire GraphQL schema. The attacker studies this structure to identify private tables, hidden fields, and relationship joins, creating targeted queries to exploit them.",
    consequence: "Full disclosure of your database schema, simplifying the task of identifying and exploiting database weaknesses.",
    fixPrompt: "Help me disable GraphQL introspection in production for my GraphQL server configuration."
  }
};

// Generates explanations for startsWith matches
function getFallbackForId(findingId, evidence = "") {
  // Exact match first
  if (STATIC_FALLBACKS[findingId]) {
    return STATIC_FALLBACKS[findingId];
  }

  // Starts with match: supabase-rls-bypass-[tableName]
  if (findingId.startsWith("supabase-rls-bypass")) {
    const tableName = findingId.split("-").pop() || "unknown";
    return {
      plainSummary: `Your database table '${tableName}' is readable by the public.`,
      attackScenario: `An attacker sends a direct request to your database REST API using your public anon key, asking for the '${tableName}' table. Because Row-Level Security (RLS) is disabled or lacks policies, the API returns all data inside the '${tableName}' table without any authorization checks.`,
      consequence: `Complete leak of all sensitive records stored in the '${tableName}' database table.`,
      fixPrompt: `Show me how to enable Row-Level Security on my Supabase table '${tableName}' and write a select policy for authenticated users.`
    };
  }

  // Starts with match: exposed-file-[fileName]
  if (findingId.startsWith("exposed-file-")) {
    const fileName = findingId.replace("exposed-file-", "");
    return {
      plainSummary: `Your configuration file '.${fileName}' is publicly downloadable.`,
      attackScenario: `An attacker types '.${fileName}' in the browser address bar (e.g. 'yoursite.com/.${fileName}'). Because your hosting root folder publishes all files, the server downloads the file to the attacker's machine, exposing database keys and secret passwords.`,
      consequence: `Severe risk of full server or API credential theft from the exposed '.${fileName}' file.`,
      fixPrompt: `Help me configure my hosting build settings to hide '.${fileName}' files, and add them to my .gitignore file.`
    };
  }

  // Starts with match: cookie-no-
  if (findingId.startsWith("cookie-no-")) {
    const flag = findingId.replace("cookie-no-", "");
    return {
      plainSummary: `A cookie set by your server is missing the secure '${flag}' flag.`,
      attackScenario: `An attacker intercepts a user's unencrypted HTTP session on a public Wi-Fi network. Because your cookie lacks the 'Secure' or 'HttpOnly' flag, the browser transmits it over insecure networks or allows malicious scripts to read it, letting the attacker hijack the session.`,
      consequence: `Moderate risk of user session hijacking if network traffic is intercepted or scripts run.`,
      fixPrompt: `Show me how to set the Secure, HttpOnly, and SameSite flags on cookies in my backend code.`
    };
  }

  // Starts with match: auth-cache-
  if (findingId.startsWith("auth-cache-")) {
    return {
      plainSummary: "Your secure authentication pages permit browser caching.",
      attackScenario: "A student logs into their account from a shared college computer. After logging out, they walk away. The next student sits down, clicks the browser's back button, and views the cached profile details of the previous student because caching was not disabled.",
      consequence: "Exposure of sensitive user dashboards to other users on shared physical computers.",
      fixPrompt: "Show me how to set the Cache-Control: no-store, no-cache response headers on my authentication pages."
    };
  }

  // Starts with match: key-
  if (findingId.startsWith("key-")) {
    const keyType = findingId.replace("key-", "").toUpperCase();
    return {
      plainSummary: `Your private ${keyType} API key is exposed in the frontend bundle.`,
      attackScenario: `An attacker opens the webpage, views the loaded JavaScript assets, and searches for key strings. They locate your hardcoded private ${keyType} key. The attacker uses this key to make requests directly to the service provider in your name, exhausting your credits.`,
      consequence: `High risk of financial costs due to billing abuse, and potential access to private third-party services.`,
      fixPrompt: `I leaked my private ${keyType} API key in my client code. Help me remove it and move the api calls to a secure backend server.`
    };
  }

  // Generic fallback if all else fails
  return {
    plainSummary: "A security vulnerability was discovered on your application.",
    attackScenario: `An attacker analyzes your site and discovers an exposure related to the scanned code. Using standard browser developer utilities, the attacker exploits this setup to bypass default controls (evidence: ${evidence || "exposed endpoint"}).`,
    consequence: "Risk of session hijacking, credentials theft, or administrative database access.",
    fixPrompt: `Fix this issue: evidence: ${evidence}. Let's write code to secure it.`
  };
}

// Calls Gemini API to get structured explanation
async function getExplanation(finding) {
  const apiKey = process.env.GEMINI_API_KEY;
  const findingId = finding.id || "";
  const evidence = finding.evidence || "";
  const title = finding.title || "";
  const category = finding.category || "";
  const severity = finding.severity || "medium";

  // Check cache first
  try {
    const cacheKey = `ai_explanation_${findingId}`;
    const cached = await db.getAiExplanation(cacheKey);
    if (cached) {
      return cached;
    }
  } catch (err) {
    // Cache read fail - proceed
  }

  const fallback = getFallbackForId(findingId, evidence);

  if (!apiKey || apiKey === "your_key_here") {
    // No API key - return static fallback
    return fallback;
  }

  // Call Gemini API
  try {
    const prompt = `You are a friendly, expert security auditor. Provide a structured explanation of this security finding to make it immediately understandable to a non-technical reader (e.g. college faculty, TPOs, or first-year students).

Finding Details:
- Title: ${title}
- Category: ${category}
- Severity: ${severity}
- Evidence: ${evidence}

Instructions:
1. "plainSummary": One sentence, absolutely NO jargon. Explain what is actually wrong in simple, plain terms (e.g. "Your website does not restrict which external sites can read your data" instead of "CORS wildcard credentials").
2. "attackScenario": 2-3 sentences describing a specific, realistic, step-by-step narrative of how a hacker would exploit THIS specific finding, referencing the real evidence if provided (e.g., table name, file name, or endpoint). Make it a narrative story, NOT a bulleted list.
3. "consequence": 1-2 sentences on what the developer/student/institution actually stands to lose (e.g. data theft, server shutdown, failed exam grade, financial bill shock). Focus on real-world outcomes, not technical details.
4. "fixPrompt": The existing copy-paste fix query. Keep this exactly or very close to: "${fallback.fixPrompt}".

Severity-Calibration rules:
- For "critical" or "high" severity: Write the attackScenario and consequence with realistic seriousness and detail.
- For "medium" severity: Keep it concrete, realistic, but slightly shorter.
- For "low" severity: Keep it very brief, calm, and matter-of-fact. Do NOT use alarming or catastrophic language.

Return a valid JSON object matching this schema:
{
  "plainSummary": "string",
  "attackScenario": "string",
  "consequence": "string",
  "fixPrompt": "string"
}`;

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
      {
        contents: [
          {
            parts: [{ text: prompt }]
          }
        ],
        generationConfig: {
          responseMimeType: "application/json"
        }
      },
      {
        timeout: 10000 // 10 seconds timeout
      }
    );

    if (
      response.status === 200 &&
      response.data &&
      response.data.candidates &&
      response.data.candidates[0] &&
      response.data.candidates[0].content &&
      response.data.candidates[0].content.parts &&
      response.data.candidates[0].content.parts[0]
    ) {
      const jsonText = response.data.candidates[0].content.parts[0].text;
      const parsed = JSON.parse(jsonText.trim());
      
      // Ensure all fields exist
      const completed = {
        plainSummary: parsed.plainSummary || fallback.plainSummary,
        attackScenario: parsed.attackScenario || fallback.attackScenario,
        consequence: parsed.consequence || fallback.consequence,
        fixPrompt: parsed.fixPrompt || fallback.fixPrompt
      };

      // Save to database cache
      try {
        const cacheKey = `ai_explanation_${findingId}`;
        await db.saveAiExplanation(cacheKey, completed);
      } catch (err) {
        // Cache write fail - proceed
      }

      return completed;
    }
  } catch (error) {
    // If Gemini call fails, default back to static fallback explanation
    console.error("Gemini explainer error, falling back to static:", error.message);
  }

  return fallback;
}

module.exports = {
  getExplanation,
  getFallbackForId
};
