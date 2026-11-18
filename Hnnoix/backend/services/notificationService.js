const nodemailer = require('nodemailer');
const config = require('../config/env');

/**
 * Delivers login codes by email. The test provider captures messages in memory
 * so automated tests never send real email or write codes to logs.
 */
class NotificationService {
  constructor() {
    this.lastDispatchedOtp = null;
    this.transporter = null;
  }

  async sendOtp({ recipient, otp, name }) {
    if (config.nodeEnv === 'test') {
      this.lastDispatchedOtp = { recipient, otp, dispatchedAt: new Date() };
      return {
        success: true,
        messageId: `TEST_MSG_${Date.now()}`,
        provider: 'TestProvider',
        recipient,
      };
    }

    if (!config.smtpUser || !config.smtpAppPassword) {
      const error = new Error('Email delivery is not configured. Set SMTP_USER and SMTP_APP_PASSWORD in backend/.env.');
      error.statusCode = 503;
      throw error;
    }

    if (!this.transporter) {
      this.transporter = nodemailer.createTransport({
        host: config.smtpHost,
        port: config.smtpPort,
        secure: config.smtpPort === 465,
        auth: {
          user: config.smtpUser,
          pass: config.smtpAppPassword,
        },
      });
    }

    let result;
    try {
      result = await this.transporter.sendMail({
        from: { name: 'Fortis Vault', address: config.smtpUser },
        to: recipient,
        subject: 'Your Fortis Vault login code',
        text: `Hello ${name},\n\nYour Fortis Vault verification code is ${otp}. It expires in ${config.otpExpiryMinutes} minutes. If you did not request this code, you can ignore this email.`,
      });
    } catch {
      const error = new Error('Unable to send the verification email. Check the Gmail SMTP settings and App Password in backend/.env.');
      error.statusCode = 502;
      throw error;
    }

    return {
      success: true,
      messageId: result.messageId,
      provider: 'Gmail SMTP',
      recipient,
    };
  }

  getLastDispatchedOtp() {
    return config.nodeEnv === 'test' ? this.lastDispatchedOtp : null;
  }
}

module.exports = new NotificationService();
