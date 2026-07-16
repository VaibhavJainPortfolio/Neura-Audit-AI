const SECRET_PATTERNS = [
  { id: "key-openai", pattern: /sk-[a-zA-Z0-9]{48}/g },
  { id: "key-openai-proj", pattern: /sk-proj-[a-zA-Z0-9_-]{40,}/g },
  { id: "key-anthropic", pattern: /sk-ant-[a-zA-Z0-9_-]{40,}/g },
  { id: "key-gemini", pattern: /AIzaSy[a-zA-Z0-9_-]{33}/g },
  { id: "key-stripe-secret", pattern: /sk_live_[a-zA-Z0-9]{24,}/g },
  { id: "key-stripe-pub", pattern: /pk_live_[a-zA-Z0-9]{24,}/g },
  { id: "key-aws-id", pattern: /AKIA[0-9A-Z]{16}/g },
  { id: "key-sendgrid", pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g },
  { id: "key-mapbox", pattern: /pk\.eyJ1[a-zA-Z0-9._-]{50,}/g },
];

function scanSecrets(content) {
  const findings = [];
  SECRET_PATTERNS.forEach((sp) => {
    let match;
    // Reset global regex index
    sp.pattern.lastIndex = 0;
    while ((match = sp.pattern.exec(content)) !== null) {
      findings.push({ id: sp.id, val: match[0] });
    }
  });
  return findings;
}

describe("Secrets Matching Regex Patterns", () => {
  test("Detects OpenAI Secret Keys", () => {
    const text = "const key = 'sk-123456789012345678901234567890123456789012345678';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({ id: "key-openai", val: "sk-123456789012345678901234567890123456789012345678" });
  });

  test("Detects OpenAI Project Keys", () => {
    const text = "const key = 'sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ_abc-def';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({
      id: "key-openai-proj",
      val: "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ_abc-def",
    });
  });

  test("Detects Anthropic API Keys", () => {
    const text = "const anthropic = 'sk-ant-sid01-1234567890ABCDEF1234567890abcdef12345678-abcdef';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({
      id: "key-anthropic",
      val: "sk-ant-sid01-1234567890ABCDEF1234567890abcdef12345678-abcdef",
    });
  });

  test("Detects Google Gemini API Keys", () => {
    const text = "export const gemini = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({ id: "key-gemini", val: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q" });
  });

  test("Detects Stripe Secret Keys", () => {
    const text = "const stripe = 'sk_l" + "ive_123456789012345678901234';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({ id: "key-stripe-secret", val: "sk_l" + "ive_123456789012345678901234" });
  });

  test("Detects AWS Access Key ID", () => {
    const text = "process.env.AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';";
    const matches = scanSecrets(text);
    expect(matches).toContainEqual({ id: "key-aws-id", val: "AKIAIOSFODNN7EXAMPLE" });
  });

  test("Does not match normal strings", () => {
    const text = "This is a normal sentence with no api keys.";
    const matches = scanSecrets(text);
    expect(matches.length).toBe(0);
  });
});
