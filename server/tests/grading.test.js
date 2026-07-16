const { calculateScoreAndGrade, calculateGradeForScan, WEIGHTS } = require("../grading_engine");

describe("Grading and Score Engine", () => {
  test("Calculates correct category scores and overall weighted average", () => {
    // 1 Medium finding in Network (-15), 1 Low finding in App Layer (-5)
    // All other categories perfect (100)
    const findings = [
      { id: "missing-csp", category: "Network", severity: "medium" },
      { id: "missing-referrer", category: "Application", severity: "low" }
    ];

    const result = calculateScoreAndGrade(findings);
    
    // Check breakdown details
    const networkCat = result.weightedBreakdown.find(c => c.key === "Network");
    const appCat = result.weightedBreakdown.find(c => c.key === "Application");
    const secretsCat = result.weightedBreakdown.find(c => c.key === "Secrets");

    expect(networkCat.score).toBe(85); // 100 - 15
    expect(appCat.score).toBe(95);     // 100 - 5
    expect(secretsCat.score).toBe(100); // 100

    // Secrets (100 * 0.20 = 20)
    // Database (100 * 0.20 = 20)
    // Network (85 * 0.15 = 12.75 -> rounded to 12.8)
    // AI/LLM (100 * 0.15 = 15)
    // App Layer (95 * 0.15 = 14.25 -> rounded to 14.3)
    // Dependencies (100 * 0.15 = 15)
    // Expected Sum = 20 + 20 + 12.8 + 15 + 14.3 + 15 = 97.1 -> rounded to 97
    expect(result.overallScore).toBe(97);
    expect(result.grade).toBe("A"); // 97 >= 90
    expect(result.capApplied).toBeNull();
  });

  test("Applies safety cap when a Critical severity finding is present", () => {
    // Secrets has critical finding (-40) -> score is 60.
    // Database has high finding (-25) -> score is 75.
    // All other categories are 100.
    const findings = [
      { id: "leaked-key", category: "Secrets", severity: "critical" },
      { id: "firebase-bypass", category: "Database", severity: "high" }
    ];

    const result = calculateScoreAndGrade(findings);

    // Weighted score would normally be:
    // Secrets: 60 * 0.2 = 12
    // Database: 75 * 0.2 = 15
    // Other 4 cats: 100 * 0.15 * 4 = 60
    // Total weighted score = 12 + 15 + 60 = 87 (which is Grade B)
    // But since there is a Critical finding, the score is capped at 64 and Grade capped at D.
    expect(result.overallScore).toBe(64);
    expect(result.grade).toBe("D");
    expect(result.capApplied).toBe("critical-finding-cap");
    expect(result.capReason).toContain("capped at D because we found a Critical severity issue");
  });

  test("Applies safety cap when a High severity finding is present", () => {
    // Network has a high finding (-25) -> score is 75.
    // All other categories are 100.
    const findings = [
      { id: "missing-csp", category: "Network", severity: "high" }
    ];

    const result = calculateScoreAndGrade(findings);

    // Weighted score would normally be:
    // Network: 75 * 0.15 = 11.25 -> 11.3
    // Other 5 cats: 100 * (0.2 + 0.2 + 0.15 + 0.15 + 0.15) = 100 * 0.85 = 85
    // Total score = 11.3 + 85 = 96.3 -> 96 (Grade A)
    // Capped at 79 and Grade C because of the High severity finding.
    expect(result.overallScore).toBe(79);
    expect(result.grade).toBe("C");
    expect(result.capApplied).toBe("high-finding-cap");
  });

  test("Does NOT cap score if the calculated score is already below the cap threshold", () => {
    // Large deductions across many categories leading to a naturally low score
    // Secrets: 0 (-100) -> 0
    // Database: 0 (-100) -> 0
    // Network: 0 (-100) -> 0
    // AI/LLM: 0 -> 0
    // All categories score = 0, overall score = 0.
    // Critical findings present. Score should naturally be 0 (Grade F), not boosted to cap 64.
    const findings = [];
    const cats = ["Secrets", "Database", "Network", "AI_LLM", "Application", "Dependencies"];
    cats.forEach(c => {
      findings.push({ id: `c1-${c}`, category: c, severity: "critical" });
      findings.push({ id: `c2-${c}`, category: c, severity: "critical" });
      findings.push({ id: `c3-${c}`, category: c, severity: "critical" });
    });

    const result = calculateScoreAndGrade(findings);
    expect(result.overallScore).toBe(0);
    expect(result.grade).toBe("F");
    expect(result.capApplied).toBeNull(); // Cap reason only shows if it actively restricted the score from being higher
  });

  test("Maps correct grade boundary thresholds", () => {
    expect(calculateGradeForScan([])).toBe("A"); // 100 -> A
  });
});
