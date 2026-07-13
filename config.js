'use strict';
if (process.env.VERCEL !== '1') {
  try { require('dotenv').config(); } catch (e) {}
}

module.exports = {
  site: {
    name:        process.env.SITE_NAME        || 'ReceOTP',
    tagline:     process.env.SITE_TAGLINE     || 'Nomor Virtual OTP Instan, Aman, Murah',
    domain:      process.env.SITE_DOMAIN      || 'https://receotp.my.id',
    logoUrl:     process.env.SITE_LOGO_URL    || '/assets/logo.png',
    faviconUrl:  process.env.SITE_FAVICON_URL || '/assets/favicon.ico',
    supportEmail:process.env.SUPPORT_EMAIL    || 'jeeyhosting@gmail.com',
    telegramSupport: process.env.TELEGRAM_SUPPORT || 'https://t.me/Jeeyhosting',
  },

  server: {
    port:       process.env.PORT || 3000,
    jwtSecret:  process.env.JWT_SECRET || 'GANTI-INI-DENGAN-STRING-ACAK-PANJANG',
    jwtExpiry:  '7d',
    cookieName: 'otp_session',
    secureCookie: process.env.VERCEL === '1' || process.env.NODE_ENV === 'production',
    cronSecret: process.env.CRON_SECRET || '',
  },

  rumahotp: {
    baseUrl: process.env.RUMAHOTP_BASE_URL || 'https://www.rumahotp.my.id',
    apiKey:  process.env.RUMAHOTP_API_KEY  || '',
  },

  pakasir: {
    baseUrl: 'https://app.pakasir.com',
    project: process.env.PAKASIR_PROJECT || '',
    apiKey:  process.env.PAKASIR_API_KEY  || '',
  },

  telegram: {
    botToken:  process.env.TELEGRAM_BOT_TOKEN  || '',
    webhookUrl: process.env.TELEGRAM_WEBHOOK_URL || '',
  },

 database: {
  uri: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/otp_store',
},

  security: {
    bcryptRounds:      10,
    maxLoginAttempts:  5,
    lockoutMs:         15 * 60 * 1000,
    otpCodeExpirySec:  5 * 60,
    otpMaxAttempts:    5,
    rateLimitWindow:   60 * 1000,
    rateLimitMax:      100,
    minPassword:       8,
  },

  pricing: {
    defaultMarkupPercent: parseFloat(process.env.DEFAULT_MARKUP || '15'),
    minDeposit:    5000,
    maxDeposit:    10_000_000,
  },
};
