// routes/contact_route.js
const express = require("express");
const nodemailer = require("nodemailer");
const router = express.Router();

router.post("/", async (req, res) => {
  const { name, email, subject, message, category } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,      // uses EMAIL
      pass: process.env.EMAIL_PASS, // uses EMAIL_PASS
    },
  });

  const mailOptions = {
    from: `"${name}" <${email}>`,
    to: process.env.SUPPORT_EMAIL || process.env.EMAIL, // destination
    subject: `[Craftique Contact] ${subject}`,
    html: `
      <h2>Contact Form Submission</h2>
      <p><b>Name:</b> ${name}</p>
      <p><b>Email:</b> ${email}</p>
      <p><b>Category:</b> ${category || "Not specified"}</p>
      <p><b>Message:</b></p>
      <p>${message.replace(/\n/g, "<br/>")}</p>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true });
  } catch (err) {
    console.error("Error sending email:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

module.exports = router;
