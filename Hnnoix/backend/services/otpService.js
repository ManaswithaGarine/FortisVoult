const crypto = require('crypto');
const config = require('../config/env');
const OtpModel = require('../models/otpModel');
const notificationService = require('./notificationService');
const logger = require('../utils/logger');

class OtpService {
  /**
   * Generates a keyed hash so the low-entropy OTP cannot be recovered from the database alone.
   */
  static hashOtp(otp) {
    return crypto.createHmac('sha256', config.jwtSecret).update(otp).digest('hex');
  }

  /**
   * Generate and dispatch a 6-digit OTP to the user's registered email address.
   */
  static async generateAndSendOtp(user, { isResend = false, otpId = null } = {}) {
    // 1. Check for active OTP and enforce cooldown
    const latestOtp = OtpModel.getLatestOtpForUser(user.id);
    if (isResend && (!latestOtp || latestOtp.id !== otpId || latestOtp.verified)) {
      const error = new Error('Verification session is no longer active. Please log in again.');
      error.statusCode = 400;
      throw error;
    }

    if (latestOtp && !latestOtp.verified) {
      const createdAtTime = new Date(latestOtp.createdAt).getTime();
      const timeSinceCreatedSeconds = Math.floor((Date.now() - createdAtTime) / 1000);
      const isExpired = Date.now() >= new Date(latestOtp.expiresAt).getTime();

      if (!isExpired && timeSinceCreatedSeconds < config.otpResendCooldownSeconds) {
        const remainingCooldown = config.otpResendCooldownSeconds - timeSinceCreatedSeconds;
        if (isResend) {
          const error = new Error(`Please wait ${remainingCooldown} seconds before requesting a new OTP.`);
          error.statusCode = 429;
          error.cooldownRemaining = remainingCooldown;
          throw error;
        }

        return {
          success: true,
          otpId: latestOtp.id,
          message: 'OTP has been sent to your registered email address. Please check your inbox.',
          expiresInSeconds: Math.max(0, Math.floor((new Date(latestOtp.expiresAt) - Date.now()) / 1000)),
          cooldownSeconds: remainingCooldown,
        };
      }
    }

    // 2. Invalidate any previous unverified OTPs
    OtpModel.invalidateUserOtps(user.id);

    // 3. Generate a cryptographically secure 6-digit OTP.
    const otp = crypto.randomInt(100000, 1000000).toString();
    const otpHash = this.hashOtp(otp);

    // 4. Calculate expiration timestamp (5 minutes)
    const expiresAt = new Date(Date.now() + config.otpExpiryMinutes * 60 * 1000).toISOString();

    // 5. Store OTP record in database
    const createdOtpRecord = OtpModel.create({
      userId: user.id,
      otpHash,
      expiresAt,
    });

    // 6. Deliver only to the registered email and invalidate the code if delivery fails.
    try {
      await notificationService.sendOtp({
        recipient: user.email,
        otp,
        name: user.name,
      });
    } catch (error) {
      OtpModel.markVerified(createdOtpRecord.id);
      throw error;
    }

    logger.security(`OTP generated for user: ${user.id}`);

    return {
      success: true,
      otpId: createdOtpRecord.id,
      message: 'OTP has been sent to your registered email address. Please check your inbox.',
      expiresInSeconds: config.otpExpiryMinutes * 60,
      cooldownSeconds: config.otpResendCooldownSeconds,
    };
  }

  /**
   * Verifies an OTP against the specific signed login challenge.
   */
  static async verifyOtp(userId, otpId, enteredOtp) {
    if (!enteredOtp || enteredOtp.trim().length !== 6) {
      const error = new Error('Please enter a valid 6-digit OTP.');
      error.statusCode = 400;
      throw error;
    }

    const latestOtp = OtpModel.findById(otpId);

    if (!latestOtp || latestOtp.userId !== userId) {
      const error = new Error('No active OTP found. Please request a new one.');
      error.statusCode = 400;
      throw error;
    }

    const currentOtp = OtpModel.getLatestOtpForUser(userId);
    if (!currentOtp || currentOtp.id !== otpId) {
      const error = new Error('This verification session is no longer active. Please log in again.');
      error.statusCode = 400;
      throw error;
    }

    // Check if already verified
    if (latestOtp.verified) {
      const error = new Error('This OTP has already been used. Please request a new one.');
      error.statusCode = 400;
      throw error;
    }

    // Check expiration
    const now = new Date();
    const expiry = new Date(latestOtp.expiresAt);
    if (now >= expiry) {
      const error = new Error('OTP has expired. Please request a new OTP.');
      error.statusCode = 400;
      throw error;
    }

    // Check maximum attempts
    if (latestOtp.attempts >= config.otpMaxAttempts) {
      const error = new Error('Maximum verification attempts exceeded. Please request a new OTP.');
      error.statusCode = 429;
      throw error;
    }

    // Increment attempts count
    const updatedOtp = OtpModel.incrementAttempts(latestOtp.id);

    // Verify hash
    const inputHash = Buffer.from(this.hashOtp(enteredOtp.trim()), 'hex');
    const storedHash = Buffer.from(latestOtp.otpHash, 'hex');
    const isValidOtp = storedHash.length === inputHash.length && crypto.timingSafeEqual(inputHash, storedHash);
    if (!isValidOtp) {
      const remainingAttempts = config.otpMaxAttempts - updatedOtp.attempts;
      logger.security(`Failed OTP attempt for user ${userId}. Remaining attempts: ${remainingAttempts}`);

      if (remainingAttempts <= 0) {
        const error = new Error('Invalid OTP. Maximum attempts reached. Please request a new OTP.');
        error.statusCode = 429;
        throw error;
      } else {
        const error = new Error(`Invalid OTP. ${remainingAttempts} attempt(s) remaining.`);
        error.statusCode = 400;
        error.remainingAttempts = remainingAttempts;
        throw error;
      }
    }

    // OTP is valid! Mark as verified
    OtpModel.markVerified(latestOtp.id);
    logger.security(`OTP successfully verified for user: ${userId}`);

    return {
      success: true,
      message: 'OTP verified successfully.',
    };
  }
}

module.exports = OtpService;
