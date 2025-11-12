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
const path = require('path'); // New: For file paths
const fs = require('fs'); // New: For saving temp files
const { python } = require('node-calls-python'); // New: For calling Python

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

// ... (This section is unchanged, so it is omitted for brevity) ...

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

// ... (This section is unchanged, so it is omitted for brevity) ...
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json()); // for parsing application/json


// --- 5. Authentication Functions (Middleware & Helpers) ---

// ... (This section is unchanged, so it is omitted for brevity) ...
// Password Hashing (Mongoose-style, using bcryptjs)
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

// ... (This section is unchanged, so it is omitted for brevity) ...
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


// --- 7. LLM Helper Function (MODIFIED) ---

/**
 * Calls the Gemini API to get a *tool suggestion* for the GP.
 * This function now implements the "Expert Collaborator" logic[cite: 95].
 * @param {string} failedFormula - The bloated formula from the "simple" GP run.
 * @param {string[]} activeOperators - The list of operators that *failed*.
 * @param {string[]} lockedOperators - The list of available new tools.
 * @returns {Promise<string>} - The name of the tool to add (e.g., "sqrt") or "None".
 */
const callGeminiForToolSuggestion = async (failedFormula, activeOperators, lockedOperators) => {
  // Define the JSON schema we want the LLM to return
  const json_schema = {
    type: "OBJECT",
    properties: {
      "tool_suggestion": {
        "type": "STRING",
        "description": `The single best tool from the LOCKED_OPERATORS list to add. Must be one of ${lockedOperators.join(', ')} or 'None'.`
      },
      "reasoning": {
        "type": "STRING",
        "description": "A brief explanation for the choice."
      }
    }
  };

  const prompt = `
    You are an expert mathematician acting as a collaborator for a Genetic Programming (GP) algorithm.
    The GP algorithm is "stuck"[cite: 96, 97]. It tried to find a formula using only the operators [${activeOperators.join(', ')}] but produced a bloated, inaccurate formula:
    
    Failed Formula: ${failedFormula}

    Your task is to suggest ONE new, non-linear tool from the "locked toolbox" that will help the GP find a simpler, more elegant solution[cite: 101, 103].

    LOCKED_OPERATORS: [${lockedOperators.join(', ')}]

    Analyze the problem and suggest the single best tool to add.
    You must only return a JSON object matching the requested schema.
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
    
    if (!json_text) {
      throw new Error("Invalid response structure from LLM.");
    }
    
    // Parse the JSON string from the LLM's text response
    const parsed_json = JSON.parse(json_text);
    
    // Validate the suggestion
    const suggestion = parsed_json.tool_suggestion;
    if (suggestion !== "None" && !lockedOperators.includes(suggestion)) {
       console.warn(`LLM suggested an invalid tool: ${suggestion}. Defaulting to 'None'.`);
       return "None";
    }

    console.log(`LLM Suggestion: Add '${suggestion}'. Reasoning: ${parsed_json.reasoning}`);
    return suggestion; // e.g., "sqrt"

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

/**
 * NEW: Helper function to run the Python GP script.
 * This is the "muscle" of the operation[cite: 39].
 * @param {string} csvPath - Path to the temporary CSV file.
 * @param {string} outputCol - The target output column name.
 * @param {string[]} activeOperators - The list of operators for the GP to use.
 * @returns {Promise<{formula: string, accuracy: number, is_bloated: boolean}>}
 */
const runPythonGP = async (csvPath, outputCol, activeOperators) => {
    console.log(`Spawning Python GP... Operators: [${activeOperators.join(', ')}]`);
    
    // Ensure the python script path is correct
    // Assumes evosolve_gp.py is in the same directory as index.js
    const pythonScript = path.join(__dirname, 'evosolve_gp.py');

    // Configure the python-bridge
    // This tells it where your Python executable is.
    // Assumes 'python' or 'python3' is in your system's PATH.
    // You might need to set a specific path, e.g., '/usr/bin/python3'
    const py = python({ pythonPath: process.env.PYTHON_PATH || 'python3' });

    try {
        // Call the 'run_gp_analysis' function inside the Python script
        const result = await py.import(pythonScript).run_gp_analysis(
            csvPath,
            outputCol,
            activeOperators
        );
        
        // The result will be a JS object automatically converted from the Python dict
        console.log("Python GP run successful:", result);
        return {
            formula: result.formula,
            accuracy: result.accuracy_score,
            is_bloated: result.is_bloated // We need this from the Python script
        };

    } catch (error) {
        console.error("Error running Python GP script:", error);
        throw new Error(`GP Analysis (Python) failed: ${error.message}`);
    }
};


// --- 8. Core API Endpoints (MODIFIED) ---

const BASIC_OPERATORS = ['add', 'sub', 'mul', 'div'];
const ADVANCED_OPERATORS = ['sqrt', 'log', 'sin', 'cos', 'exp'];

app.get('/api/functions', (req, res) => {
  res.status(200).json({
    basic: BASIC_OPERATORS,
    advanced: ADVANCED_OPERATORS
  });
});

// POST /analyze (Protected, HEAVILY MODIFIED)
app.post('/analyze', authenticateUser, upload.single('file'), async (req, res) => {
  
  // --- 0. Create a temporary file path for the CSV ---
  // The Python script needs to read the file from disk.
  const tempCsvPath = path.join(__dirname, `temp_${req.user.id}_${Date.now()}.csv`);

  try {
    const { output_column } = req.body;
    if (!req.file || !output_column) {
      return res.status(400).json({ detail: "File or output column missing." });
    }
    
    // --- 1. Save CSV to a temporary file ---
    // We must write the buffer to disk so the Python script can read it
    await fs.promises.writeFile(tempCsvPath, req.file.buffer);

    // --- 2. Run Analysis Run 1: Simple Mode (GP "Muscle") ---
    // This run uses only basic tools [+, -, *, /][cite: 13, 97].
    console.log("--- Analysis Run 1: Simple Mode GP ---");
    let simple_result = await runPythonGP(tempCsvPath, output_column, BASIC_OPERATORS);
    
    let final_formula = simple_result.formula;
    let final_accuracy = simple_result.accuracy;

    // --- 3. Check for failure (Bloat or Low Accuracy) [cite: 16, 98] ---
    // We check for 'is_bloated' which the Python script must provide.
    // This aligns with the PDF's logic[cite: 16].
    if (simple_result.is_bloated || final_accuracy < 0.95) {
      console.log(`--- Simple run failed (Accuracy: ${final_accuracy}, Bloated: ${simple_result.is_bloated}). Triggering Metamorphosis... ---`);
      
      // --- 4. The "Expert Consultation" (LLM "Brain") [cite: 95, 100] ---
      // Send the *failed* formula to the LLM for advice.
      const tool_to_add = await callGeminiForToolSuggestion(
          simple_result.formula, // The bloated formula [cite: 18]
          BASIC_OPERATORS,
          ADVANCED_OPERATORS
      );

      if (tool_to_add && tool_to_add !== "None") {
        // --- 5. The Metamorphosis (Add the new tool) [cite: 21, 31] ---
        const metamorphic_operators = [...BASIC_OPERATORS, tool_to_add];
        
        console.log(`--- Analysis Run 2: Metamorphic Mode (Operators: [${metamorphic_operators.join(', ')}]) ---`);
        let metamorphic_result = await runPythonGP(tempCsvPath, output_column, metamorphic_operators);
        
        // Only use the new result if it's *actually* better
        if (metamorphic_result.accuracy > final_accuracy) {
          console.log(`--- Metamorphic run succeeded! New Accuracy: ${metamorphic_result.accuracy} ---`);
          final_formula = metamorphic_result.formula;
          final_accuracy = metamorphic_result.accuracy;
        } else {
          console.log("--- Metamorphic run did not improve accuracy. Keeping simple formula. ---");
        }
      } else {
         console.log("--- LLM suggested 'None' or failed. Sticking with simple result. ---");
      }

    } else {
      console.log(`--- Simple run sufficient (Accuracy: ${final_accuracy}, Bloated: ${simple_result.is_bloated}) ---`);
    }

    if (!final_formula || final_accuracy === undefined) {
      return res.status(500).json({ detail: "GP/LLM failed to return a valid formula." });
    }

    // --- 6. Save to Database (Mongoose Version) ---
    const newResult = await AnalysisResult.create({
      userId: req.user.id, // req.user.id is from our auth middleware
      filename: req.file.originalname,
      outputColumn: output_column,
      formulaString: final_formula,
      accuracyScore: final_accuracy
    });

    // --- 7. Return the new result ---
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
  } finally {
    // --- 8. Cleanup: Delete the temporary file ---
    try {
        await fs.promises.unlink(tempCsvPath);
        console.log("Cleaned up temporary CSV file.");
    } catch (err) {
        console.error("Error cleaning up temporary file:", err);
    }
  }
});


// GET /history (Protected, Mongoose Version)
// ... (This section is unchanged, so it is omitted for brevity) ...
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

// ... (This section is unchanged, so it is omitted for brevity) ...
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