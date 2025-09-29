"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendPasswordResetOtp = void 0;
// emailService.ts
const nodemailer_1 = __importDefault(require("nodemailer"));
// Configure your email transporter
// IMPORTANT: Use environment variables for your email credentials!
const transporter = nodemailer_1.default.createTransport({
    service: 'Gmail', // or another service like SendGrid, Mailgun etc.
    auth: {
        user: process.env.EMAIL_USER, // your email address
        pass: process.env.EMAIL_PASS, // your email password or app-specific password
    },
});
const sendPasswordResetOtp = async (email, otp) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Password Reset OTP',
        html: `<p>Your One-Time Password for resetting your password is: <strong>${otp}</strong></p><p>This OTP will expire in 10 minutes.</p>`,
    };
    await transporter.sendMail(mailOptions);
};
exports.sendPasswordResetOtp = sendPasswordResetOtp;
