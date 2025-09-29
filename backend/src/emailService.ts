// emailService.ts
import nodemailer from 'nodemailer';

// Configure your email transporter
// IMPORTANT: Use environment variables for your email credentials!
const transporter = nodemailer.createTransport({
    service: 'Gmail', // or another service like SendGrid, Mailgun etc.
    auth: {
        user: process.env.EMAIL_USER, // your email address
        pass: process.env.EMAIL_PASS, // your email password or app-specific password
    },
});

export const sendPasswordResetOtp = async (email: string, otp: string) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Password Reset OTP',
        html: `<p>Your One-Time Password for resetting your password is: <strong>${otp}</strong></p><p>This OTP will expire in 10 minutes.</p>`,
    };

    await transporter.sendMail(mailOptions);
};