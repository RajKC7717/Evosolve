// --- 1. Imports & Setup ---

// Load environment variables from .env file FIRST
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose'); // New: Mongoose for MongoDB
const bcrypt = require('bcryptjs'); // Using bcryptjs
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const csv = require('csv-parser');
const axios = require('axios');
const { Readable } = require('stream');

// --- 2. Configuration & Secrets ---

// Load secrets from .env file
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 8000;

// Validate that all secrets are loaded
if (!GEMINI_API_KEY || !MONGO_URI || !JWT_SECRET) {
  console.error("FATAL ERROR: Missing environment variables (GEMINI_API_KEY, MONGO_URI, JWT_SECRET).");
  console.error("Please create a .env file with these values.");
  process.exit(1); // Exit the application if secrets are missing
}

const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${GEMINI_API_KEY}`;

// --- 3. Mongoose (MongoDB) Database Setup ---

// Define Mongoose Schemas (replaces Sequelize models)
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  }
}, { timestamps: true }); // Adds createdAt & updatedAt

const AnalysisResultSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Links to the User model
    required: true,
  },
  filename: {
    type: String,
    required: true,
  },
  outputColumn: {
    type: String,
    required: true,
  },
  formulaString: {
    type: String,
    required: true,
  },
  accuracyScore: {
    type: Number,
    required: true,
  }
}, { timestamps: true });

// Create Models from Schemas
const User = mongoose.model('User', UserSchema);
const AnalysisResult = mongoose.model('AnalysisResult', AnalysisResultSchema);

// --- 4. Express App & Middleware ---

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json()); // for parsing application/json

// --- 5. Authentication Functions (Middleware & Helpers) ---

// Password Hashing (Mongoose-style, using bcryptjs)
// We'll add this as a "pre-save hook" to the UserSchema
// This automatically hashes the password *before* it's saved
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Password comparison helper
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// JWT Authentication Middleware
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ detail: "Authentication failed: No token provided." });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Attach user's ID to the request object for protected routes
    req.user = { id: payload.userId, email: payload.email }; 
    next();
  } catch (error) {
    res.status(401).json({ detail: "Authentication failed: Invalid token." });
  }
};

// --- 6. Auth API Endpoints (Rewritten for Mongoose) ---

app.get("/", (req, res) => {
  res.send("Evosolve JS backend (MongoDB Version) is running!");
});

// POST /register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ detail: "Please provide email and password." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ detail: "Email already registered." });
    }
    
    // Create new user (password will be auto-hashed by the 'pre-save' hook)
    const user = new User({ email, password });
    await user.save();

    // Create token
    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '24h',
    });

    res.status(201).json({ access_token: token, token_type: "bearer" });

  } catch (error) {
    res.status(500).json({ detail: `Registration failed: ${error.message}` });
  }
});

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ detail: "Please provide email and password." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ detail: "Invalid credentials." });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ detail: "Invalid credentials." });
    }

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '24h',
    });

    res.status(200).json({ access_token: token, token_type: "bearer" });

  } catch (error) {
    res.status(500).json({ detail: `Login failed: ${error.message}` });
  }
});

// GET /me (Protected)
app.get('/me', authenticateUser, async (req, res) => {
  // We re-fetch the user from DB to ensure data is fresh
  // (req.user.id was attached by the middleware)
  try {
    const user = await User.findById(req.user.id).select('-password'); // -password excludes it
    if (!user) {
      return res.status(404).json({ detail: "User not found." });
    }
    res.status(200).json({
      id: user._id,
      email: user.email,
      createdAt: user.createdAt
    });
  } catch (error) {
    res.status(500).json({ detail: `Error fetching user: ${error.message}` });
  }
});

// --- 7. LLM Helper Function (Now uses the API Key) ---

/**
 * Calls the Gemini API to get a formula for the given data.
 * @param {string} dataSample - A CSV string sample of the data.
 * @param {string[]} inputCols - List of input column names.
 * @param {string} outputCol - The target output column name.
 * @param {boolean} simpleMode - If true, restricts the LLM to basic math.
 * @returns {Promise<{formula: string, accuracy: number}>}
 */
const callGeminiForFormula = async (dataSample, inputCols, outputCol, simpleMode) => {
  // Define the JSON schema we want the LLM to return
  const json_schema = {
    type: "OBJECT",
    properties: {
      "formula": {
        "type": "STRING",
        "description": "The mathematical formula, e.g., 'add(mul(a, 2), b)' or 'a * 2 + b'"
      },
      "accuracy_r_squared": {
        "type": "NUMBER",
        "description": "The R-squared accuracy of the formula, from 0.0 to 1.0"
      }
    }
  };

  // Define the constraints for the LLM based on simpleMode
  let function_constraint = "You may only use basic arithmetic operators: add, sub, mul, div.";
  if (!simpleMode) {
    function_constraint = "You are encouraged to use more complex functions if they improve accuracy, such as: sqrt, log, sin, cos, exp.";
  }

  const prompt = `
    You are an expert data scientist performing symbolic regression.
    Your task is to find the simplest, most accurate mathematical formula that
    predicts the output column '${outputCol}' from the input columns: ${inputCols}.

    Here is a sample of the data (in CSV format):
    ${dataSample}

    Constraints:
    - ${function_constraint}
    - The formula must be as simple as possible (parsimonious).
    - Accuracy is measured by R-squared (a value between 0.0 and 1.0).
    - You must only return a JSON object matching the requested schema.

    Analyze the data and return the best formula you can find.
    `;

  const payload = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      responseMimeType: "application/json",
      responseSchema: json_schema
    }
  };

  try {
    // Make the API call to Gemini
    const response = await axios.post(GEMINI_API_URL, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000 // 30 second timeout
    });
   
    const result = response.data;
    const json_text = result?.candidates?.[0]?.content?.parts?.[0]?.text;
    console.log(result);
    if (!json_text) {
      throw new Error("Invalid response structure from LLM.");
    }
    
    // Parse the JSON string from the LLM's text response
    const parsed_json = JSON.parse(json_text);
    
    return {
      formula: parsed_json.formula,
      accuracy: parsed_json.accuracy_r_squared
    };

  } catch (error) {
    if (error.response) {
      console.error(`Gemini API call failed with status ${error.response.status}:`, error.response.data);
      throw new Error(`LLM Analysis failed: ${error.response.data?.error?.message || error.message}`);
    } else {
      console.error(`Gemini API call failed: ${error.message}`);
      throw new Error(`LLM Analysis failed: ${error.message}`);
    }
  }
};


// --- 8. Core API Endpoints (Rewritten for Mongoose) ---

app.get('/api/functions', (req, res) => {
  res.status(200).json({
    basic: ['add', 'sub', 'mul', 'div'],
    advanced: ['sqrt', 'log', 'sin', 'cos', 'exp']
  });
});

// POST /analyze (Protected)
app.post('/analyze', authenticateUser, upload.single('file'), async (req, res) => {
  try {
    const { output_column } = req.body;
    if (!req.file || !output_column) {
      return res.status(400).json({ detail: "File or output column missing." });
    }
    
    // --- 1. Parse CSV (same as before) ---
    const data = [];
    const fileBuffer = req.file.buffer;
    const readable = new Readable();
    readable._read = () => {}; 
    readable.push(fileBuffer);
    readable.push(null);

    // Use a Promise to handle the stream
    await new Promise((resolve, reject) => {
      readable.pipe(csv())
        .on('data', (row) => data.push(row))
        .on('end', resolve)
        .on('error', reject);
    });

    if (data.length === 0) {
      return res.status(400).json({ detail: "CSV file is empty or invalid." });
    }
    const headers = Object.keys(data[0]);
    if (!headers.includes(output_column)) {
      return res.status(400).json({ detail: `Output column '${output_column}' not found.` });
    }
    const inputCols = headers.filter(h => h !== output_column);
    if (inputCols.length === 0) {
      return res.status(400).json({ detail: "No input columns found (only output column)._c" });
    }
    
    // Create the data sample string for the LLM
    const dataSample = [
      headers.join(','), // Header row
      ...data.slice(0, 50).map(row => headers.map(h => row[h]).join(',')) // First 50 rows
    ].join('\n');

    // --- 2. Run Metamorphic Workflow ---
    console.log("--- Analysis Run 1: Simple Mode ---");
    let simple_result = await callGeminiForFormula(dataSample, inputCols, output_column, true);
    
    let final_formula = simple_result.formula;
    let final_accuracy = simple_result.accuracy;

    // 3. Check score. If it's bad, try the Metamorphic run.
    if (final_accuracy < 0.95) {
      console.log(`--- Simple run failed (Accuracy: ${final_accuracy}). Trying Metamorphic Mode... ---`);
      let metamorphic_result = await callGeminiForFormula(dataSample, inputCols, output_column, false);
      
      // Only use the new result if it's *actually* better
      if (metamorphic_result.accuracy > final_accuracy) {
        console.log(`--- Metamorphic run succeeded! New Accuracy: ${metamorphic_result.accuracy} ---`);
        final_formula = metamorphic_result.formula;
        final_accuracy = metamorphic_result.accuracy;
      } else {
         console.log("--- Metamorphic run did not improve accuracy. Keeping simple formula. ---");
      }
    } else {
      console.log(`--- Simple run sufficient (Accuracy: ${final_accuracy}) ---`);
    }

    if (!final_formula || final_accuracy === undefined) {
      return res.status(500).json({ detail: "LLM failed to return a valid formula." });
    }

    // --- 4. Save to Database (Mongoose Version) ---
    const newResult = await AnalysisResult.create({
      userId: req.user.id, // req.user.id is from our auth middleware
      filename: req.file.originalname,
      outputColumn: output_column,
      formulaString: final_formula,
      accuracyScore: final_accuracy
    });

    // --- 5. Return the new result ---
    res.status(201).json({
      id: newResult._id, // MongoDB uses _id
      filename: newResult.filename,
      output_column: newResult.outputColumn,
      formula: newResult.formulaString, // Match frontend expectation
      accuracy_score: newResult.accuracyScore, // Match frontend expectation
      created_at: newResult.createdAt
    });

  } catch (error) {
    console.error("Analysis Error:", error);
    res.status(500).json({ detail: `Analysis failed: ${error.message}` });
  }
});

// GET /history (Protected, Mongoose Version)
app.get('/history', authenticateUser, async (req, res) => {
  try {
    // Find all results for the logged-in user and sort by newest first
    const results = await AnalysisResult.find({ userId: req.user.id })
      .sort({ createdAt: -1 }); // Mongoose sort syntax
    
    // Format the results to match frontend expectations
    const formattedResults = results.map(item => ({
      id: item._id, // MongoDB uses _id
      filename: item.filename,
      output_column: item.outputColumn,
      formula_string: item.formulaString, // Match frontend expectation
      accuracy_score: item.accuracyScore, // Match frontend expectation
      created_at: item.createdAt
    }));

    res.status(200).json(formattedResults);
  } catch (error) {
    res.status(500).json({ detail: `Failed to fetch history: ${error.message}` });
  }
});


// --- 9. Server Start ---

const startServer = async () => {
  try {
    // Connect to MongoDB using the URI from .env
    await mongoose.connect(MONGO_URI);
    console.log("Successfully connected to MongoDB.");

    // Start Express server
    app.listen(PORT, () => {
      console.log(`Evosolve JS backend (MongoDB) running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB.", error);
    process.exit(1);
  }
};

startServer();