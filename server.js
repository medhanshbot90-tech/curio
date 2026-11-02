
require("dotenv").config();
const dns = require("node:dns");
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const express = require("express");
const cors = require("cors");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { InferenceClient } = require("@huggingface/inference");

const User = require("./models/User");
const app = express();

// ===============================
// CONFIGURATION
// ===============================

const MONGODB_URI = process.env.MONGODB_URI;
const GEMINI_KEY = process.env.GEMINI_API_KEY;
const GROQ_KEY = process.env.GROQ_API_KEY;
const OPENROUTER_KEY = process.env.OPENROUTER_KEY;
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;
const HUGGINGFACE_TOKEN = process.env.HUGGINGFACE_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;

const GEMINI_MODEL = "gemini-3.8-flash";
const GROQ_MODEL = "openai/gpt-oss-120b";
const OPENROUTER_MODEL = "meta-llama/llama-3.1-8b-instruct";
const IMAGE_MODEL = "black-forest-labs/FLUX.1-Krea-dev";

const GEMINI_TIMEOUT = 5000;
const GROQ_TIMEOUT = 5000;
const OPENROUTER_TIMEOUT = 5000;
const TAVILY_TIMEOUT = 5000;

const MAX_HISTORY_MESSAGES = 20;
const MAX_MESSAGE_LENGTH = 20000;

const hf = HUGGINGFACE_TOKEN
  ? new InferenceClient(HUGGINGFACE_TOKEN)
  : null;

const fetch = globalThis.fetch;

if (!MONGODB_URI) {
  console.error("MONGODB_URI is missing.");
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(() => console.log("MongoDB Connected Successfully"))
    .catch((error) =>
      console.error("MongoDB Connection Error:", error.message)
    );
}

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(__dirname, { index: false }));

// ===============================
// CHAT HISTORY
// ===============================

// Note: This is in-memory shared history, not per-user history.
let chatHistory = [];

// ===============================
// AI SYSTEM PROMPT
// ===============================


const SYSTEM_PROMPT = `
You are Curio, a modern, intelligent and friendly AI assistant.

IDENTITY
- Your name is Curio.
- You were created by Medhansh Bisht.
- If asked who created you, reply:
  "I was created by Medhansh Bisht 😎🔥"
- Never claim to be human or pretend to have real emotions.

PERSONALITY
- Be friendly, thoughtful, confident and approachable.
- Communicate naturally, like a helpful intelligent assistant.
- Use light humour when appropriate.
- Be respectful, patient and encouraging.
- Never sound rude, arrogant or unnecessarily robotic.
- Do not force jokes, emojis or greetings into every reply.

COMMUNICATION
- Match the user's language and communication style.
- Understand Hindi, English and Hinglish.
- Answer the actual question directly.
- Keep simple answers short and explain complex topics properly.
- Remember relevant details from the current conversation.
- Never ask for information already provided.
- Ask only one clear question when clarification is necessary.

SMART MODES
1. STUDY MODE
   Explain concepts simply with examples.
   Adapt explanations to the student's level.
   Encourage understanding instead of memorisation.

2. CODING MODE
   Write clean, readable and practical code.
   Explain important changes.
   Preserve existing functionality.
   Never claim code was tested unless it was.

3. CREATIVE MODE
   Help with brainstorming, writing, ideas and projects.
   Be imaginative while keeping suggestions useful.

4. PROFESSIONAL MODE
   Use a polished, precise and structured tone.
   Prioritise accuracy and clarity.

5. CASUAL MODE
   Be relaxed, friendly and conversational.
   Use appropriate humour without becoming distracting.

ACCURACY AND SAFETY
- Never invent facts, sources or capabilities.
- Be honest about uncertainty.
- Protect private information and API keys.
- Follow applicable safety requirements.
- Do not pretend to remember information unavailable in context.

RESPONSE STYLE
- Use headings and lists only when useful.
- Avoid repetitive introductions.
- Do not overuse emojis.
- Give practical and meaningful answers.
- Adapt naturally to the situation.

CORE MISSION
Help people learn, explore, create, solve problems
and think more confidently.

Every interaction should feel clear, helpful and natural.
`;

// ===============================
// COOKIE HELPERS
// ===============================

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;

  for (const cookie of cookieHeader.split(";")) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      try {
        return decodeURIComponent(valueParts.join("="));
      } catch {
        return null;
      }
    }
  }

  return null;
}

function setAuthCookie(res, token) {
  const parts = [
    `curio_token=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Max-Age=2592000"
  ];

  if (process.env.NODE_ENV === "production") {
    parts.push("Secure");
  }

  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearAuthCookie(res) {
  const parts = [
    "curio_token=",
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Max-Age=0"
  ];

  if (process.env.NODE_ENV === "production") {
    parts.push("Secure");
  }

  res.setHeader("Set-Cookie", parts.join("; "));
}

// ===============================
// AUTHENTICATION
// ===============================

async function requireAuth(req, res, next) {
  try {
    if (!JWT_SECRET) {
      console.error("JWT_SECRET is missing.");

      return res.status(500).json({
        success: false,
        message: "Server authentication is not configured."
      });
    }

    const token = getCookie(req, "curio_token");

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded.userId) {
      return res.status(401).json({
        success: false,
        message: "Invalid authentication token."
      });
    }

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication Error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// ===============================
// SIGNUP
// ===============================

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required."
      });
    }

    const cleanName = String(name).trim();
    const cleanEmail = String(email).trim().toLowerCase();

    if (cleanName.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid name."
      });
    }

    if (cleanEmail.length < 5 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters."
      });
    }

    const existingUser = await User.findOne({ email: cleanEmail });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword
    });

    await user.save();

    return res.json({
      success: true,
      message: "Account created successfully."
    });
  } catch (error) {
    console.error("Signup Error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to create account."
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: cleanEmail });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    if (!JWT_SECRET) {
      console.error("JWT_SECRET is missing.");

      return res.status(500).json({
        success: false,
        message: "Server authentication is not configured."
      });
    }

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    setAuthCookie(res, token);

    return res.json({
      success: true,
      message: "Login successful.",
      user: {
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login Error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to login."
    });
  }
});

// ===============================
// AUTH ME
// ===============================

app.get("/auth/me", requireAuth, async (req, res) => {
  return res.json({
    success: true,
    user: {
      name: req.user.name,
      email: req.user.email
    }
  });
});

// ===============================
// LOGOUT
// ===============================

app.post("/logout", (req, res) => {
  clearAuthCookie(res);

  return res.json({
    success: true,
    message: "Logged out successfully."
  });
});

// ===============================
// ANSWER VALIDATION
// ===============================

function isUsableAnswer(reply) {
  if (typeof reply !== "string") return false;

  const text = reply.trim();
  if (text.length < 2) return false;

  const badResponses = [
    "i don't know",
    "i do not know",
    "i can't help",
    "i cannot help",
    "i'm not sure",
    "i am not sure",
    "no answer"
  ];

  return !badResponses.includes(text.toLowerCase());
}

// ===============================
// TAVILY WEB SEARCH
// ===============================

async function searchWeb(query) {
  try {
    if (!TAVILY_API_KEY) {
      console.log("TAVILY_API_KEY missing.");
      return { text: "", sources: [] };
    }

    const response = await fetch("https://api.tavily.com/search", {
      method: "POST",
      signal: AbortSignal.timeout(TAVILY_TIMEOUT),
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        api_key: TAVILY_API_KEY,
        query,
        search_depth: "advanced",
        include_answer: true,
        include_raw_content: false,
        max_results: 5
      })
    });

    if (!response.ok) {
      console.error("Tavily Error:", response.status);
      return { text: "", sources: [] };
    }

    const data = await response.json();
    const results = Array.isArray(data.results) ? data.results : [];

    const sources = results
      .filter((item) => item.url)
      .map((item) => ({
        title: item.title || "Source",
        url: item.url
      }));

    let text = data.answer || "";

    if (!text) {
      text = results
        .map((item) => `${item.title || "Source"}: ${item.content || ""}`)
        .join("\n\n");
    }

    return { text, sources };
  } catch (error) {
    console.error(
      "Tavily Search Error:",
      error.name === "TimeoutError" || error.name === "AbortError"
        ? "Request timed out."
        : error.message
    );

    return { text: "", sources: [] };
  }
}

// ===============================
// GEMINI
// ===============================

async function askGemini(messages) {
  try {
    if (!GEMINI_KEY) return null;

    // Gemini uses systemInstruction for the system prompt.
    // System messages must not be converted into user messages.
    const systemText = messages
      .filter((message) => message.role === "system")
      .map((message) => message.content)
      .join("\n\n");

    const contents = messages
      .filter(
        (message) =>
          message.role === "user" || message.role === "assistant"
      )
      .map((message) => ({
        role: message.role === "assistant" ? "model" : "user",
        parts: [{ text: String(message.content) }]
      }));

    if (!contents.length) return null;

    const requestBody = {
      contents,
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 4096
      }
    };

    if (systemText) {
      requestBody.systemInstruction = {
        parts: [{ text: systemText }]
      };
    }

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY}`,
      {
        method: "POST",
        signal: AbortSignal.timeout(GEMINI_TIMEOUT),
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(requestBody)
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Gemini Error:", response.status, errorText.slice(0, 300));
      return null;
    }

    const data = await response.json();
    const reply = data?.candidates?.[0]?.content?.parts
      ?.map((part) => part.text || "")
      .join("");

    return isUsableAnswer(reply) ? reply.trim() : null;
  } catch (error) {
    console.error(
      "Gemini Error:",
      error.name === "TimeoutError" || error.name === "AbortError"
        ? "Request timed out."
        : error.message
    );

    return null;
  }
}

// ===============================
// GROQ
// ===============================

async function askGroq(messages) {
  try {
    if (!GROQ_KEY) return null;

    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        signal: AbortSignal.timeout(GROQ_TIMEOUT),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${GROQ_KEY}`
        },
        body: JSON.stringify({
          model: GROQ_MODEL,
          messages,
          temperature: 0.7,
          max_tokens: 4096
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Groq Error:", response.status, errorText.slice(0, 300));
      return null;
    }

    const data = await response.json();
    const reply = data?.choices?.[0]?.message?.content;

    return isUsableAnswer(reply) ? reply.trim() : null;
  } catch (error) {
    console.error(
      "Groq Error:",
      error.name === "TimeoutError" || error.name === "AbortError"
        ? "Request timed out."
        : error.message
    );

    return null;
  }
}

// ===============================
// OPENROUTER
// ===============================

async function askOpenRouter(messages) {
  try {
    if (!OPENROUTER_KEY) return null;

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        signal: AbortSignal.timeout(OPENROUTER_TIMEOUT),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${OPENROUTER_KEY}`,
          "HTTP-Referer": "https://curio-x8mx.onrender.com",
          "X-Title": "Curio AI"
        },
        body: JSON.stringify({
          model: OPENROUTER_MODEL,
          messages,
          temperature: 0.7,
          max_tokens: 4096
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error(
        "OpenRouter Error:",
        response.status,
        errorText.slice(0, 300)
      );
      return null;
    }

    const data = await response.json();
    const reply = data?.choices?.[0]?.message?.content;

    return isUsableAnswer(reply) ? reply.trim() : null;
  } catch (error) {
    console.error(
      "OpenRouter Error:",
      error.name === "TimeoutError" || error.name === "AbortError"
        ? "Request timed out."
        : error.message
    );

    return null;
  }
}

// ===============================
// HUGGING FACE IMAGE GENERATION
// ===============================

app.post("/generate-image", requireAuth, async (req, res) => {
  try {
    const { prompt } = req.body || {};

    if (!prompt || !String(prompt).trim()) {
      return res.status(400).json({
        success: false,
        message: "Image prompt is required."
      });
    }

    if (!HUGGINGFACE_TOKEN || !hf) {
      return res.status(500).json({
        success: false,
        message: "Hugging Face is not configured."
      });
    }

    const cleanPrompt = String(prompt).trim();

    console.log("Generating image request.");

    const image = await hf.textToImage({
      model: IMAGE_MODEL,
      inputs: cleanPrompt
    });

    const imageBuffer = Buffer.from(await image.arrayBuffer());
    const imageBase64 = imageBuffer.toString("base64");

    return res.json({
      success: true,
      image: `data:image/png;base64,${imageBase64}`,
      provider: "Hugging Face",
      model: IMAGE_MODEL
    });
  } catch (error) {
    console.error("Hugging Face Image Error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to generate image right now."
    });
  }
});

// ===============================
// CHAT
// ===============================

app.post("/chat", requireAuth, async (req, res) => {
  try {
    const { message, web } = req.body || {};

    if (typeof message !== "string" || !message.trim()) {
      return res.status(400).json({
        success: false,
        message: "Message is required."
      });
    }

    const userMessage = message.trim();

    if (userMessage.length > MAX_MESSAGE_LENGTH) {
      return res.status(413).json({
        success: false,
        message: "Message is too long. Please shorten it and try again."
      });
    }

    let webUsed = false;
    let sources = [];
    let webText = "";

    // Search only when the frontend explicitly enables web search.
    if (web === true) {
      const webResult = await searchWeb(userMessage);

      webText = webResult.text;
      sources = webResult.sources;
      webUsed = Boolean(webText);
    }

    // Build the system instructions and optional web context.
    const systemMessages = [
      {
        role: "system",
        content: SYSTEM_PROMPT
      }
    ];

    if (webText) {
      systemMessages.push({
        role: "system",
        content:
          "Web search results are provided below. Use them when relevant, " +
          "prioritize reliable and recent information, and do not invent " +
          "details that are not supported by the results.\n\n" +
          webText
      });
    }

    // Keep only the most recent messages to control context size.
    const recentHistory = chatHistory.slice(-MAX_HISTORY_MESSAGES);

    const messages = [
      ...systemMessages,
      ...recentHistory,
      {
        role: "user",
        content: userMessage
      }
    ];

    let reply = null;
    let provider = null;

    // 1. Gemini
    reply = await askGemini(messages);

    if (reply) {
      provider = "Gemini";
    }

    // 2. Groq
    if (!reply) {
      reply = await askGroq(messages);

      if (reply) {
        provider = "Groq";
      }
    }

    // 3. OpenRouter
    if (!reply) {
      reply = await askOpenRouter(messages);

      if (reply) {
        provider = "OpenRouter";
      }
    }

    // 4. Tavily fallback if every AI provider fails.
    if (!reply) {
      console.log("All AI providers failed. Trying Tavily fallback.");

      let fallbackWeb = {
        text: webText,
        sources
      };

      if (!fallbackWeb.text) {
        fallbackWeb = await searchWeb(userMessage);
      }

      if (fallbackWeb.text) {
        reply = fallbackWeb.text;
        sources = fallbackWeb.sources;
        webUsed = true;
        provider = "Tavily Web Search";
      }
    }

    if (!reply) {
      reply =
        "Sorry, I couldn't get a useful answer right now. " +
        "Please try again in a moment.";
      provider = "Fallback";
    }

    // Keep the existing in-memory history behavior.
    chatHistory.push(
      { role: "user", content: userMessage },
      { role: "assistant", content: reply }
    );

    // Bound the amount of history held in memory.
    if (chatHistory.length > MAX_HISTORY_MESSAGES) {
      chatHistory = chatHistory.slice(-MAX_HISTORY_MESSAGES);
    }

    return res.json({
      success: true,
      reply,
      webUsed,
      sources,
      provider
    });
  } catch (error) {
    console.error("Chat Error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Something went wrong while processing your message."
    });
  }
});

// ===============================
// RESET CHAT
// ===============================

app.post("/reset", requireAuth, (req, res) => {
  chatHistory = [];

  return res.json({
    success: true,
    message: "Chat reset successfully."
  });
});

// ===============================
// SERVER
// ===============================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Curio Running On Port ${PORT}`);
});
