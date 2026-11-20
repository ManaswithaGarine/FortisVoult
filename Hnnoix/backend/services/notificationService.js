
const config = require('../config/env');

class NotificationService {
  constructor() {
    this.lastDispatchedOtp = null;
  }

  async sendOtp({ recipient, otp, name }) {
    // Preserve the existing test-mode behavior.
    if (config.nodeEnv === 'test') {
      this.lastDispatchedOtp = {
        recipient,
        otp,
        dispatchedAt: new Date(),
      };

      return {
        success: true,
        message: 'Test OTP generated successfully.',
        recipient,
      };
    }

    if (!config.resendApiKey) {
      throw new Error('RESEND_API_KEY is not configured.');
    }

    if (!config.emailFrom) {
      throw new Error('EMAIL_FROM is not configured.');
    }

    const payload = {
      from: `Fortis Vault <${config.emailFrom}>`,
      to: [recipient],
      subject: 'Your Fortis Vault login code',
      text: [
        `Hello ${name},`,
        '',
        `Your Fortis Vault verification code is: ${otp}`,
        '',
        `This code expires in ${config.otpExpiryMinutes} minutes.`,
        '',
        'If you did not request this code, please ignore this email.',
        '',
        'Fortis Vault Security Team',
      ].join('\n'),
    };

    let response;

    try {
      response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${config.resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      console.error('Resend network error:', error.message);

      throw new Error('Unable to connect to the email service.');
    }

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      console.error('Resend API error:', {
        status: response.status,
        message: result.message || result.error || 'Email delivery failed',
      });

      throw new Error('Unable to send OTP email.');
    }

    return {
      success: true,
      messageId: result.id,
      provider: 'Resend',
      recipient,
    };
  }

  getLastDispatchedOtp() {
    return config.nodeEnv === 'test'
      ? this.lastDispatchedOtp
      : null;
  }
}

module.exports = new NotificationService();
