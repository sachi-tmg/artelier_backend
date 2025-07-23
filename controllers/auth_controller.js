// controllers/authController.js
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

exports.setupMFA = async (req, res) => {
  const user = await User.findById(req.user.id);
  
  // Generate secret
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `Artelier (${user.email})`,
    issuer: 'Artelier'
  });

  // Generate QR code image
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  // Save secret to user (don't share this!)
  user.mfaSecret = secret.base32;
  await user.save();

  // Show QR code and manual entry code
  res.json({
    qrCodeUrl,  // Display this as an <img> in frontend
    manualCode: secret.base32,  // Let users type this manually
    mfaEnabled: false  // Not enabled until verified
  });
};


exports.verifyMFA = async (req, res) => {
  const { code } = req.body;
  const user = await User.findById(req.user.id);

  // Verify code
  const verified = speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: code,
    window: 1  // Allows 30s time drift
  });

  if (!verified) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  // Generate backup codes
  const backupCodes = Array.from({ length: 10 }, () => ({
    code: crypto.randomBytes(4).toString('hex').toUpperCase(),
    used: false
  }));

  // Enable MFA
  user.mfaEnabled = true;
  user.backupCodes = backupCodes;
  await user.save();

  res.json({
    success: true,
    backupCodes: backupCodes.map(b => b.code), // Show to user ONCE
    mfaEnabled: true
  });
};