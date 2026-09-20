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
// MONGODB
// ===============================

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("MONGODB_URI is missing.");
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(() => {
      console.log("MongoDB Connected Successfully");
    })
    .catch((error) => {
      console.error("MongoDB Connection Error:", error);
    });
}


// ===============================
// MIDDLEWARE
// ===============================

app.use(cors());
app.use(express.json());

app.use(
  express.static(__dirname, {
    index: false
  })
);


// ===============================
// ENVIRONMENT VARIABLES
// ===============================

const GEMINI_KEY = process.env.GEMINI_API_KEY;
const GROQ_KEY = process.env.GROQ_API_KEY;
const OPENROUTER_KEY = process.env.OPENROUTER_KEY;
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;

const HUGGINGFACE_TOKEN =
  process.env.HUGGINGFACE_TOKEN;

const JWT_SECRET = process.env.JWT_SECRET;


// ===============================
// HUGGING FACE
// ===============================

const hf = HUGGINGFACE_TOKEN
  ? new InferenceClient(HUGGINGFACE_TOKEN)
  : null;


// ===============================
// MODELS
// ===============================

const GEMINI_MODEL = "gemini-2.5-flash";

const GROQ_MODEL =
  "llama-3.3-70b-versatile";

const OPENROUTER_MODEL =
  "meta-llama/llama-3.1-8b-instruct";

const IMAGE_MODEL =
  "black-forest-labs/FLUX.1-Krea-dev";


// ===============================
// CHAT HISTORY
// ===============================

let chatHistory = [];


// ===============================
// NODE FETCH
// ===============================

let fetch;

(async () => {
  const module = await import("node-fetch");
  fetch = module.default;
})();


// ===============================
// COOKIE HELPERS
// ===============================

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] =
      cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(
        valueParts.join("=")
      );
    }
  }

  return null;
}


function setAuthCookie(res, token) {
  const isProduction =
    process.env.NODE_ENV === "production";

  const cookieParts = [
    `curio_token=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Max-Age=2592000"
  ];

  if (isProduction) {
    cookieParts.push("Secure");
  }

  res.setHeader(
    "Set-Cookie",
    cookieParts.join("; ")
  );
}


function clearAuthCookie(res) {
  const isProduction =
    process.env.NODE_ENV === "production";

  const cookieParts = [
    "curio_token=",
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    "Max-Age=0"
  ];

  if (isProduction) {
    cookieParts.push("Secure");
  }

  res.setHeader(
    "Set-Cookie",
    cookieParts.join("; ")
  );
}


// ===============================
// AUTH MIDDLEWARE
// ===============================

async function requireAuth(req, res, next) {
  try {
    if (!JWT_SECRET) {
      console.error(
        "JWT_SECRET is missing."
      );

      return res.status(500).json({
        success: false,
        message:
          "Server authentication is not configured."
      });
    }

    const token = getCookie(
      req,
      "curio_token"
    );

    if (!token) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication required."
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (!decoded.userId) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid authentication token."
      });
    }

    const user =
      await User.findById(
        decoded.userId
      ).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message:
          "User not found."
      });
    }

    req.user = user;

    next();

  } catch (error) {
    console.error(
      "Authentication Error:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired session."
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

app.post(
  "/signup",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and password are required."
        });
      }

      const cleanName =
        String(name).trim();

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      if (cleanName.length < 2) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter a valid name."
        });
      }

      if (cleanEmail.length < 5) {
        return res.status(400).json({
          success: false,
          message:
            "Please enter a valid email."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must be at least 6 characters."
        });
      }

      const existingUser =
        await User.findOne({
          email: cleanEmail
        });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists."
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          10
        );

      const user =
        new User({
          name: cleanName,
          email: cleanEmail,
          password: hashedPassword
        });

      await user.save();

      return res.json({
        success: true,
        message:
          "Account created successfully."
      });

    } catch (error) {
      console.error(
        "Signup Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create account."
      });
    }
  }
);


// ===============================
// LOGIN
// ===============================

app.post(
  "/login",
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Email and password are required."
        });
      }

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email: cleanEmail
        });

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password."
        });
      }

      const passwordMatch =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!passwordMatch) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid email or password."
        });
      }

      if (!JWT_SECRET) {
        console.error(
          "JWT_SECRET is missing."
        );

        return res.status(500).json({
          success: false,
          message:
            "Server authentication is not configured."
        });
      }

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),
            email:
              user.email
          },
          JWT_SECRET,
          {
            expiresIn: "30d"
          }
        );

      setAuthCookie(
        res,
        token
      );

      return res.json({
        success: true,
        message:
          "Login successful.",
        user: {
          name: user.name,
          email: user.email
        }
      });

    } catch (error) {
      console.error(
        "Login Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to login."
      });
    }
  }
);


// ===============================
// AUTH ME
// ===============================

app.get(
  "/auth/me",
  requireAuth,
  async (req, res) => {
    return res.json({
      success: true,
      user: {
        name: req.user.name,
        email: req.user.email
      }
    });
  }
);


// ===============================
// LOGOUT
// ===============================

app.post(
  "/logout",
  (req, res) => {
    clearAuthCookie(res);

    return res.json({
      success: true,
      message:
        "Logged out successfully."
    });
  }
);


// ===============================
// TAVILY WEB SEARCH
// ===============================

async function searchWeb(query) {
  try {
    if (!TAVILY_API_KEY) {
      console.log(
        "TAVILY_API_KEY missing."
      );

      return {
        text: "",
        sources: []
      };
    }

    const response =
      await fetch(
        "https://api.tavily.com/search",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            api_key:
              TAVILY_API_KEY,
            query,
            search_depth:
              "advanced",
            include_answer:
              true,
            include_raw_content:
              false,
            max_results: 5
          })
        }
      );

    if (!response.ok) {
      console.error(
        "Tavily Error:",
        response.status
      );

      return {
        text: "",
        sources: []
      };
    }

    const data =
      await response.json();

    const results =
      data.results || [];

    const sources =
      results.map((item) => ({
        title:
          item.title || "Source",
        url:
          item.url || ""
      }));

    let text =
      data.answer || "";

    if (!text) {
      text =
        results
          .map(
            (item) =>
              `${item.title}: ${
                item.content || ""
              }`
          )
          .join("\n\n");
    }

    return {
      text,
      sources
    };

  } catch (error) {
    console.error(
      "Tavily Search Error:",
      error
    );

    return {
      text: "",
      sources: []
    };
  }
}


// ===============================
// AUTO WEB SEARCH CHECK
// ===============================

async function needsWebSearch(
  message
) {
  try {
    if (!OPENROUTER_KEY) {
      return false;
    }

    const response =
      await fetch(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
            Authorization:
              `Bearer ${OPENROUTER_KEY}`
          },
          body: JSON.stringify({
            model:
              OPENROUTER_MODEL,
            messages: [
              {
                role:
                  "system",
                content:
                  "Decide if the user's question requires current, live, recent, changing, or web-based information. Reply ONLY with YES or NO."
              },
              {
                role:
                  "user",
                content:
                  message
              }
            ],
            temperature: 0
          })
        }
      );

    if (!response.ok) {
      return false;
    }

    const data =
      await response.json();

    const answer =
      data
        ?.choices?.[0]
        ?.message
        ?.content
        ?.trim()
        ?.toUpperCase();

    return answer === "YES";

  } catch (error) {
    console.error(
      "Web Detection Error:",
      error.message
    );

    return false;
  }
}


// ===============================
// ANSWER CHECK
// ===============================

function isUsableAnswer(reply) {
  if (!reply) {
    return false;
  }

  const text =
    String(reply).trim();

  if (text.length < 2) {
    return false;
  }

  const badResponses = [
    "i don't know",
    "i do not know",
    "i can't help",
    "i cannot help",
    "i'm not sure",
    "i am not sure",
    "no answer"
  ];

  const lower =
    text.toLowerCase();

  for (const bad of badResponses) {
    if (lower === bad) {
      return false;
    }
  }

  return true;
}


// ===============================
// GEMINI
// ===============================

async function askGemini(
  messages
) {
  try {
    if (!GEMINI_KEY) {
      return null;
    }

    const contents =
      messages.map(
        (message) => ({
          role:
            message.role ===
            "assistant"
              ? "model"
              : "user",
          parts: [
            {
              text:
                message.content
            }
          ]
        })
      );

    const response =
      await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            contents
          })
        }
      );

    if (!response.ok) {
      const errorText =
        await response.text();

      console.error(
        "Gemini Error:",
        errorText
      );

      return null;
    }

    const data =
      await response.json();

    const reply =
      data
        ?.candidates?.[0]
        ?.content
        ?.parts?.[0]
        ?.text;

    return isUsableAnswer(
      reply
    )
      ? reply
      : null;

  } catch (error) {
    console.error(
      "Gemini Error:",
      error
    );

    return null;
  }
}


// ===============================
// GROQ
// ===============================

async function askGroq(
  messages
) {
  try {
    if (!GROQ_KEY) {
      return null;
    }

    const response =
      await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
            Authorization:
              `Bearer ${GROQ_KEY}`
          },
          body: JSON.stringify({
            model:
              GROQ_MODEL,
            messages,
            temperature: 0.7
          })
        }
      );

    if (!response.ok) {
      const errorText =
        await response.text();

      console.error(
        "Groq Error:",
        errorText
      );

      return null;
    }

    const data =
      await response.json();

    const reply =
      data
        ?.choices?.[0]
        ?.message
        ?.content;

    return isUsableAnswer(
      reply
    )
      ? reply
      : null;

  } catch (error) {
    console.error(
      "Groq Error:",
      error
    );

    return null;
  }
}


// ===============================
// OPENROUTER
// ===============================

async function askOpenRouter(
  messages
) {
  try {
    if (!OPENROUTER_KEY) {
      return null;
    }

    const response =
      await fetch(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
            Authorization:
              `Bearer ${OPENROUTER_KEY}`,
            "HTTP-Referer":
              "https://curio-x8mx.onrender.com",
            "X-Title":
              "Curio AI"
          },
          body: JSON.stringify({
            model:
              OPENROUTER_MODEL,
            messages,
            temperature: 0.7
          })
        }
      );

    if (!response.ok) {
      const errorText =
        await response.text();

      console.error(
        "OpenRouter Error:",
        errorText
      );

      return null;
    }

    const data =
      await response.json();

    const reply =
      data
        ?.choices?.[0]
        ?.message
        ?.content;

    return isUsableAnswer(
      reply
    )
      ? reply
      : null;

  } catch (error) {
    console.error(
      "OpenRouter Error:",
      error
    );

    return null;
  }
}


// ===============================
// HUGGING FACE IMAGE GENERATION
// ===============================

app.post(
  "/generate-image",
  requireAuth,
  async (req, res) => {
    try {
      const {
        prompt
      } = req.body;

      if (
        !prompt ||
        !String(prompt).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Image prompt is required."
        });
      }

      if (!HUGGINGFACE_TOKEN || !hf) {
        return res.status(500).json({
          success: false,
          message:
            "Hugging Face is not configured."
        });
      }

      const cleanPrompt =
        String(prompt).trim();

      console.log(
        "Generating image:",
        cleanPrompt
      );

      const image =
        await hf.textToImage({
          model:
            IMAGE_MODEL,
          inputs:
            cleanPrompt
        });

      const imageBuffer =
        Buffer.from(
          await image.arrayBuffer()
        );

      const imageBase64 =
        imageBuffer.toString(
          "base64"
        );

      return res.json({
        success: true,
        image:
          `data:image/png;base64,${imageBase64}`,
        provider:
          "Hugging Face",
        model:
          IMAGE_MODEL
      });

    } catch (error) {
      console.error(
        "Hugging Face Image Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to generate image right now."
      });
    }
  }
);


// ===============================
// CHAT
// ===============================

app.post(
  "/chat",
  requireAuth,
  async (req, res) => {
    try {
      const {
        message,
        web
      } = req.body;

      if (
        !message ||
        !String(message).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Message is required."
        });
      }

      const userMessage =
        String(message).trim();

      let webUsed = false;
      let sources = [];
      let webText = "";

      if (web === true) {
        webUsed = true;
      } else {
        webUsed =
          await needsWebSearch(
            userMessage
          );
      }

      if (webUsed) {
        const webResult =
          await searchWeb(
            userMessage
          );

        webText =
          webResult.text;

        sources =
          webResult.sources;
      }

      const systemPrompt = `
You are Curio, a smart and friendly AI assistant.

Be helpful, clear, accurate and natural.

If the user asks who created, made, developed, owns, or built you, reply exactly:
"I was created by Medhansh Bisht 😎🔥"

Do not claim to be ChatGPT.

If web search information is provided, use it when relevant and do not invent facts.

Keep answers appropriate and useful for the user.
`;

      const messages = [
        {
          role: "system",
          content:
            systemPrompt
        },
        ...chatHistory,
        {
          role: "user",
          content:
            userMessage
        }
      ];

      if (webText) {
        messages.splice(
          1,
          0,
          {
            role: "system",
            content:
              `Web search information:\n\n${webText}`
          }
        );
      }

      chatHistory.push({
        role: "user",
        content:
          userMessage
      });

      let reply = null;
      let provider = null;

      reply =
        await askGemini(
          messages
        );

      if (reply) {
        provider =
          "Gemini";
      }

      if (!reply) {
        reply =
          await askGroq(
            messages
          );

        if (reply) {
          provider =
            "Groq";
        }
      }

      if (!reply) {
        reply =
          await askOpenRouter(
            messages
          );

        if (reply) {
          provider =
            "OpenRouter";
        }
      }

      if (!reply) {
        console.log(
          "All AI providers failed. Using Tavily fallback."
        );

        const fallbackWeb =
          await searchWeb(
            userMessage
          );

        if (fallbackWeb.text) {
          webUsed = true;

          sources =
            fallbackWeb.sources;

          const fallbackMessages = [
            {
              role: "system",
              content:
                `${systemPrompt}

Use the following web search information to answer the user's question accurately:

${fallbackWeb.text}`
            },
            {
              role: "user",
              content:
                userMessage
            }
          ];

          reply =
            await askOpenRouter(
              fallbackMessages
            );

          if (reply) {
            provider =
              "Tavily + OpenRouter";
          }
        }
      }

      if (!reply) {
        reply =
          "Sorry, I couldn't get a useful answer right now. Please try again.";

        provider =
          "Fallback";
      }

      chatHistory.push({
        role: "assistant",
        content:
          reply
      });

      return res.json({
        success: true,
        reply,
        webUsed,
        sources,
        provider
      });

    } catch (error) {
      console.error(
        "Chat Error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Something went wrong while processing your message."
      });
    }
  }
);


// ===============================
// RESET CHAT
// ===============================

app.post(
  "/reset",
  requireAuth,
  (req, res) => {
    chatHistory = [];

    return res.json({
      success: true,
      message:
        "Chat reset successfully."
    });
  }
);


// ===============================
// SERVER
// ===============================

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  () => {
    console.log(
      `Curio Running On Port ${PORT}`
    );
  }
);
