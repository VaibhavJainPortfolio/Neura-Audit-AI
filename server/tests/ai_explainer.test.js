const { getFallbackForId, getExplanation } = require("../ai_explainer");

describe("AI Explainer and Jargon-Free Translator", () => {
  describe("Static Fallback Mapping", () => {
    test("Maps all four fields for a High/Critical finding with appropriate seriousness", () => {
      const fallback = getFallbackForId("exposed-supabase-service-role");
      expect(fallback).toHaveProperty("plainSummary");
      expect(fallback).toHaveProperty("attackScenario");
      expect(fallback).toHaveProperty("consequence");
      expect(fallback).toHaveProperty("fixPrompt");

      // Verify severity-calibration seriousness
      expect(fallback.plainSummary).toContain("exposed");
      expect(fallback.attackScenario).toContain("bypassing Row-Level Security");
      expect(fallback.consequence).toContain("catastrophic data breach");
    });

    test("Maps all four fields for a Low finding with calmer, shorter descriptions", () => {
      const fallback = getFallbackForId("header-missing-referrer-policy");
      expect(fallback).toHaveProperty("plainSummary");
      expect(fallback).toHaveProperty("attackScenario");
      expect(fallback).toHaveProperty("consequence");
      expect(fallback).toHaveProperty("fixPrompt");

      // Verify calmer severity-calibration
      expect(fallback.attackScenario).toContain("clicks an external link");
      expect(fallback.consequence).toContain("Minor exposure");
      expect(fallback.consequence).not.toContain("catastrophic");
      expect(fallback.consequence).not.toContain("compromise");
    });

    test("Supports startsWith prefix parsing for dynamic Supabase tables", () => {
      const fallback = getFallbackForId("supabase-rls-bypass-orders");
      expect(fallback.plainSummary).toContain("table 'orders'");
      expect(fallback.attackScenario).toContain("orders");
      expect(fallback.consequence).toContain("orders");
    });
  });

  describe("API Integration and Fallback handling", () => {
    test("Falls back to static explanation structure when GEMINI_API_KEY is missing", async () => {
      // Mock process.env
      const originalKey = process.env.GEMINI_API_KEY;
      delete process.env.GEMINI_API_KEY;

      const result = await getExplanation({
        id: "header-missing-content-security-policy",
        title: "Missing Content-Security-Policy header",
        severity: "high",
        evidence: "Missing CSP"
      });

      expect(result.plainSummary).toBe("Your website lacks a Content Security Policy (CSP) header.");
      expect(result.attackScenario).toContain("inject a malicious script");

      // Restore key
      process.env.GEMINI_API_KEY = originalKey;
    });
  });
});
