// routes/contact_route.js
const express = require("express");
const nodemailer = require("nodemailer");
const InputSanitizer = require('../utils/sanitizer');
const AuditLogger = require('../services/audit_logger');
const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const { name, email, subject, message, category } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Check for XSS in contact form
    if (InputSanitizer.containsXSS(name) || 
        InputSanitizer.containsXSS(subject) || 
        InputSanitizer.containsXSS(message)) {
      
      // Log security incident
      await AuditLogger.log({
        action: 'security_violation',
        resource: '/api/contact',
        method: 'POST',
        status: 'blocked',
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        details: { 
          violation_type: 'xss_attempt_in_contact_form',
          fields_affected: [
            InputSanitizer.containsXSS(name) ? 'name' : null,
            InputSanitizer.containsXSS(subject) ? 'subject' : null,
            InputSanitizer.containsXSS(message) ? 'message' : null
          ].filter(Boolean)
        }
      });

      return res.status(400).json({
        error: 'Your message could not be sent due to invalid content',
        code: 'INVALID_CONTENT'
      });
    }

    // Sanitize all inputs (already done by middleware, but double-check)
    const sanitizedData = {
      name: InputSanitizer.sanitizeText(name, 100),
      email: InputSanitizer.sanitizeEmail(email),
      subject: InputSanitizer.sanitizeText(subject, 200),
      message: InputSanitizer.sanitizeText(message, 1000),
      category: category ? InputSanitizer.sanitizeText(category, 50) : null
    };

    const transporter = nodemailer.createTransporter({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,      // uses EMAIL
        pass: process.env.EMAIL_PASS, // uses EMAIL_PASS
      },
    });

    const mailOptions = {
      from: `"${sanitizedData.name}" <${sanitizedData.email}>`,
      to: process.env.SUPPORT_EMAIL || process.env.EMAIL, // destination
      subject: `[Artelier Contact] ${sanitizedData.subject}`,
      html: `
        <h2>Contact Form Submission</h2>
        <p><b>Name:</b> ${sanitizedData.name}</p>
        <p><b>Email:</b> ${sanitizedData.email}</p>
        <p><b>Category:</b> ${sanitizedData.category || "Not specified"}</p>
        <p><b>Message:</b></p>
        <p>${sanitizedData.message.replace(/\n/g, "<br/>")}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    
    // Log successful contact form submission
    await AuditLogger.log({
      action: 'contact_form_submission',
      resource: '/api/contact',
      method: 'POST',
      status: 'success',
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      details: { 
        sender_email: sanitizedData.email,
        subject: sanitizedData.subject,
        category: sanitizedData.category
      }
    });
    
    res.json({ success: true });
  } catch (err) {
    console.error("Error sending email:", err);
    
    // Log contact form error
    await AuditLogger.log({
      action: 'contact_form_error',
      resource: '/api/contact',
      method: 'POST',
      status: 'error',
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      details: { error: err.message }
    });
    
    res.status(500).json({ error: "Failed to send message" });
  }
});

module.exports = router;
