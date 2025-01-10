const express = require('express');
const home = express.Router();
const users = require("../models/users.model");
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Email transporter configuration
const transporter = nodemailer.createTransport({
    secure: true,
    host: 'smtp.gmail.com',
    port: 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// User Registration
home.post("/register", async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({
            message: "Please provide all required fields",
            success: false,
        });
    }

    try {
        const existingUser = await users.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists", success: false });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new users({ username, password: hashedPassword, email });
        await newUser.save();

        res.status(201).json({ message: "User created successfully", success: true });
    } catch (err) {
        res.status(500).json({
            message: "Server error. Please try again later.",
            success: false,
            error: err.message,
        });
    }
});

// User Login
home.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username
        const user = await users.findOne({ username });
        if (!user) {
            return res.status(400).json({ 
                message: "Invalid username or password", 
                success: false 
            });
        }

        // Compare the provided password with the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ 
                message: "Invalid username or password", 
                success: false 
            });
        }

        
        const token = jwt.sign(
            { id: user._id }, 
            process.env.SECRET_KEY, 
            { expiresIn: '1h' } 
        );

        
        res.status(200).json({ 
            message: "Logged in successfully", 
            success: true, 
            token 
        });
    } catch (err) {
        res.status(500).json({
            message: "Server error. Please try again later.",
            success: false,
            error: err.message,
        });
    }
});


// Forgot Password
home.post("/forget-password", async (req, res) => {
    const { username } = req.body;

    try {
        const user = await users.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: "User not found", success: false });
        }

        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000;

        user.resetpasswordtoken = token;
        user.resetpasswordexpires = expires;
        await user.save();

        const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset',
            html: `
                <p>Hello, ${user.username}. You requested a password reset.</p>
                <p>Click the link below to reset your password:</p>
                <a href="${resetLink}">Reset Your Password</a>
                <p>If you did not request this, please ignore this email. The link will expire in 1 hour.</p>
            `,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: "Password reset email sent successfully", success: true });
    } catch (error) {
        res.status(503).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message,
        });
    }
});

// Verify Reset Token
home.get("/verify-token/:token", async (req, res) => {
    const { token } = req.params;

    try {
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token", success: false });
        }

        res.status(200).json({ message: "Token is valid", success: true });
    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message,
        });
    }
});

// Reset Password
home.post("/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const user = await users.findOne({
            resetpasswordtoken: token,
            resetpasswordexpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token", success: false });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetpasswordtoken = undefined;
        user.resetpasswordexpires = undefined;

        await user.save();

        res.status(200).json({ message: "Password successfully reset", success: true });
    } catch (error) {
        res.status(500).json({
            message: "Something went wrong on the server side",
            success: false,
            error: error.message,
        });
    }
});

module.exports = home;
