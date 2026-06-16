require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);
app.use(express.json({ limit: "10kb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  message: { error: "Too many requests. Please try again later." },
});
app.use("/api/", limiter);

// Gemini AI setup
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Build the analysis prompt
function buildPrompt(message) {
  return `You are an expert fraud analyst specializing in scholarship and job offer scams. Analyze the following message and respond ONLY with a valid JSON object (no markdown, no extra text).

Message to analyze:
"""
${message}
"""

Respond with this exact JSON structure:
{
  "scamProbability": <number 0-100>,
  "riskLevel": "<Low|Medium|High>",
  "verdict": "<one sentence summary>",
  "redFlags": [<list of specific suspicious elements found, empty array if none>],
  "legitimateSignals": [<list of genuine signals if any, empty array if none>],
  "explanation": "<detailed 2-3 paragraph explanation of why this message is or isn't suspicious>",
  "recommendations": [<list of 3-5 actionable safety steps for the recipient>],
  "category": "<Scholarship Scam|Job Scam|Legitimate Scholarship|Legitimate Job|Phishing|Other>"
}

Rules:
- scamProbability 0-30 = Low risk, 31-69 = Medium risk, 70-100 = High risk
- riskLevel must match scamProbability range
- Be specific about red flags, reference actual text from the message
- Recommendations should be practical and actionable`;
}

// Analyze endpoint
app.post("/api/analyze", async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || typeof message !== "string") {
      return res.status(400).json({ error: "Message text is required." });
    }

    const trimmed = message.trim();
    if (trimmed.length < 20) {
      return res
        .status(400)
        .json({ error: "Message is too short to analyze. Please provide more text." });
    }
    if (trimmed.length > 5000) {
      return res
        .status(400)
        .json({ error: "Message is too long. Please limit to 5000 characters." });
    }

    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === "your_gemini_api_key_here") {
      return res.status(500).json({
        error: "Gemini API key is not configured. Please set GEMINI_API_KEY in your .env file.",
      });
    }

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    const prompt = buildPrompt(trimmed);

    const result = await model.generateContent(prompt);
    const responseText = result.response.text();

    // Strip markdown fences if present
    const clean = responseText
      .replace(/```json\s*/gi, "")
      .replace(/```\s*/g, "")
      .trim();

    let analysis;
    try {
      analysis = JSON.parse(clean);
    } catch {
      console.error("Gemini raw response:", responseText);
      return res.status(500).json({ error: "Failed to parse AI response. Please try again." });
    }

    // Validate and sanitize fields
    const scamProbability = Math.min(100, Math.max(0, Number(analysis.scamProbability) || 0));
    let riskLevel = analysis.riskLevel;
    if (!["Low", "Medium", "High"].includes(riskLevel)) {
      riskLevel = scamProbability >= 70 ? "High" : scamProbability >= 31 ? "Medium" : "Low";
    }

    res.json({
      scamProbability,
      riskLevel,
      verdict: analysis.verdict || "Analysis complete.",
      redFlags: Array.isArray(analysis.redFlags) ? analysis.redFlags : [],
      legitimateSignals: Array.isArray(analysis.legitimateSignals) ? analysis.legitimateSignals : [],
      explanation: analysis.explanation || "",
      recommendations: Array.isArray(analysis.recommendations) ? analysis.recommendations : [],
      category: analysis.category || "Other",
      analyzedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Analysis error:", err);
    if (err.message?.includes("API_KEY")) {
      return res.status(401).json({ error: "Invalid Gemini API key." });
    }
    if (err.message?.includes("quota") || err.message?.includes("429")) {
      return res.status(429).json({ error: "Gemini API quota exceeded. Try again later." });
    }
    res.status(500).json({ error: "Analysis failed. Please try again." });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    geminiConfigured: !!(
      process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "your_gemini_api_key_here"
    ),
  });
});

app.listen(PORT, () => {
  console.log(`🛡️  Scam Detector backend running on port ${PORT}`);
  console.log(
    `   Gemini API: ${process.env.GEMINI_API_KEY ? "✅ configured" : "❌ not configured"}`
  );
});
