const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// JWT secret key
const JWT_SECRET = "your-secure-jwt-secret"; // Replace with an environment variable in production

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "users", // Replace with your database name
});

db.connect((err) => {
    if (err) {
        console.error("Error connecting to MySQL:", err);
        return;
    }
    console.log("Connected to MySQL database!");
});

// Create table if not exists
db.query(
    `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100)
    )`,
    (err) => {
        if (err) console.error("Error creating users table:", err);
        else console.log("Users table created or already exists!");
    }
);

// API to handle user registration
app.post("/register", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    // Hash the password before storing it
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).json({ error: "Internal server error!" });
        }

        // Insert the user into the database
        const sql = `INSERT INTO users (email, password) VALUES (?, ?)`;
        db.query(sql, [email, hashedPassword], (err) => {
            if (err) {
                console.error("Error inserting user:", err);
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(409).json({ error: "Email already exists!" });
                }
                return res.status(500).json({ error: "Database error!" });
            }
            res.status(201).json({ message: "User registered successfully!" });
        });
    });
});

// API to handle user login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.query(sql, [email], (err, result) => {
        if (err) {
            console.error("Error during login:", err);
            return res.status(500).json({ error: "Database error!" });
        }

        if (result.length === 0) {
            return res.status(401).json({ error: "Invalid email or password!" });
        }

        // Compare the entered password with the hashed password in the database
        bcrypt.compare(password, result[0].password, (err, isMatch) => {
            if (err) {
                console.error("Error comparing passwords:", err);
                return res.status(500).json({ error: "Internal server error!" });
            }

            if (!isMatch) {
                return res.status(401).json({ error: "Invalid email or password!" });
            }

            // Generate JWT token
            const token = jwt.sign({ id: result[0].id }, JWT_SECRET, { expiresIn: "1h" });
            res.status(200).json({ message: "Login successful!", token });
        });
    });
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(401).json({ error: "Access denied, token missing!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Invalid or expired token!" });
        }
        req.user = decoded;
        next();
    });
};

// API to fetch user profile (protected route)
app.get("/profile", verifyToken, (req, res) => {
    const sql = `SELECT id, email FROM users WHERE id = ?`;
    db.query(sql, [req.user.id], (err, result) => {
        if (err) {
            console.error("Error fetching user profile:", err);
            return res.status(500).json({ error: "Database error!" });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: "User not found!" });
        }

        res.status(200).json({ user: result[0] });
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
