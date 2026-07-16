// Grading Constants
const WEIGHT_SECRETS = 0.20;
const WEIGHT_DATABASE = 0.20;
const WEIGHT_NETWORK = 0.15;
const WEIGHT_AI_LLM = 0.15;
const WEIGHT_APPLICATION = 0.15;
const WEIGHT_DEPENDENCIES = 0.15;

const CAP_CRITICAL_GRADE = "D";
const CAP_CRITICAL_SCORE = 64;
const CAP_HIGH_GRADE = "C";
const CAP_HIGH_SCORE = 79;

const THRESHOLD_A = 90;
const THRESHOLD_B = 80;
const THRESHOLD_C = 65;
const THRESHOLD_D = 50;

// Grade and Score calculator utility
function calculateScoreAndGrade(findings) {
  const categories = [
    { name: "Secrets", key: "Secrets", weight: WEIGHT_SECRETS },
    { name: "Database", key: "Database", weight: WEIGHT_DATABASE },
    { name: "Network", key: "Network", weight: WEIGHT_NETWORK },
    { name: "AI/LLM Exposure", key: "AI_LLM", weight: WEIGHT_AI_LLM },
    { name: "App Layer", key: "Application", weight: WEIGHT_APPLICATION },
    { name: "Dependencies", key: "Dependencies", weight: WEIGHT_DEPENDENCIES }
  ];

  const weightedBreakdown = categories.map(cat => {
    let deductions = 0;
    findings.forEach(f => {
      if (f.category === cat.key) {
        if (f.severity === "critical") deductions += 40;
        else if (f.severity === "high") deductions += 25;
        else if (f.severity === "medium") deductions += 15;
        else if (f.severity === "low") deductions += 5;
      }
    });

    const score = Math.max(0, 100 - deductions);
    const contribution = Math.round(score * cat.weight * 10) / 10;

    return {
      category: cat.name,
      key: cat.key,
      score,
      weight: cat.weight,
      contributionToOverall: contribution
    };
  });

  // Calculate overall weighted score
  const sumOfContributions = weightedBreakdown.reduce((sum, item) => sum + item.contributionToOverall, 0);
  let overallScore = Math.min(100, Math.max(0, Math.round(sumOfContributions)));

  // Check for caps
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;

  let capApplied = null;
  let capReason = null;

  if (criticalCount > 0) {
    if (overallScore > CAP_CRITICAL_SCORE) {
      overallScore = CAP_CRITICAL_SCORE;
      capApplied = "critical-finding-cap";
      capReason = `Your grade is capped at ${CAP_CRITICAL_GRADE} because we found a Critical severity issue — fixing all other categories to 100% won't raise your grade above ${CAP_CRITICAL_GRADE} until the Critical issue is resolved.`;
    }
  } else if (highCount > 0) {
    if (overallScore > CAP_HIGH_SCORE) {
      overallScore = CAP_HIGH_SCORE;
      capApplied = "high-finding-cap";
      capReason = `Your grade is capped at ${CAP_HIGH_GRADE} because we found a High severity issue — fixing all other categories to 100% won't raise your grade above ${CAP_HIGH_GRADE} until the High issue is resolved.`;
    }
  }

  // Map score to letter grade
  let grade = "F";
  if (overallScore >= THRESHOLD_A) grade = "A";
  else if (overallScore >= THRESHOLD_B) grade = "B";
  else if (overallScore >= THRESHOLD_C) grade = "C";
  else if (overallScore >= THRESHOLD_D) grade = "D";

  // Force grade override if score cap is active but rounding caused threshold mismatch
  if (criticalCount > 0 && (grade === "A" || grade === "B" || grade === "C")) {
    grade = "D";
  }
  if (highCount > 0 && (grade === "A" || grade === "B")) {
    grade = "C";
  }

  return {
    overallScore,
    grade,
    weightedBreakdown,
    capApplied,
    capReason
  };
}

function calculateGradeForScan(findings) {
  const result = calculateScoreAndGrade(findings);
  return result.grade;
}

module.exports = {
  calculateScoreAndGrade,
  calculateGradeForScan,
  WEIGHTS: {
    Secrets: WEIGHT_SECRETS,
    Database: WEIGHT_DATABASE,
    Network: WEIGHT_NETWORK,
    AI_LLM: WEIGHT_AI_LLM,
    Application: WEIGHT_APPLICATION,
    Dependencies: WEIGHT_DEPENDENCIES
  }
};
