const express = require("express");
const router = express.Router();
const { getEsewaPaymentHash, verifyEsewaPayment } = require("../services/esewa_service");
const Payment = require("../models/payment");
const { verifyJWT } = require("../controllers/creation_controller");

console.log("--- Loading paymentRoutes.js ---"); // Add this

// Initialize eSewa payment
router.post("/initialize-esewa", verifyJWT, async (req, res) => { // <-- Add verifyJWT here
    console.log("Backend: /api/payment/initialize-esewa POST hit!");
    console.log("Backend: Request body:", req.body);
    // Now you can access user ID from req.user
    const userIdFromToken = req.user.userId; // Assuming your JWT payload has an 'id' field for the user
    console.log("Backend: User ID from token:", userIdFromToken); // Verify it's not undefined

    try {
        const { amount, orderId } = req.body; // Remove userId from destructuring, use from token

        console.log("Backend: Attempting to create Payment record...");
        const payment = await Payment.create({
            transactionId: `INIT-${Date.now()}`,
            amount: amount,
            paymentMethod: "esewa",
            status: "pending",
            orderReference: orderId,
            user: userIdFromToken, // Use userId from token
        });
        console.log("Backend: Payment record created:", payment);

      // Generate eSewa payment data
      const paymentData = await getEsewaPaymentHash({
        amount: amount,
        transaction_uuid: payment._id.toString(), // Using payment ID as UUID
      });

      // Update with the transaction_uuid
      payment.transaction_uuid = payment._id.toString();
      await payment.save();

      res.json({
        success: true,
        payment: {
          amount: amount,
          transaction_uuid: payment._id.toString(),
          product_code: process.env.ESEWA_PRODUCT_CODE,
          signed_field_names: paymentData.signed_field_names,
          signature: paymentData.signature,
        },
      });
    } catch (error) {
        console.error("Backend: Error in /initialize-esewa:", error); // Add this
        res.status(500).json({
            success: false,
            message: "Failed to initialize payment",
            error: error.message,
        });
    }
});

// Verify eSewa payment (callback)
router.post("/verify-esewa", async (req, res) => {
    console.log("eSewa verification endpoint hit");

    const { data, paymentId } = req.query; // `paymentId` here is crucial for finding the correct record
    const FRONTEND_ORIGIN = process.env.FRONTEND_URL || "https://localhost:5173";

    if (!data) {
        console.error("Missing eSewa data parameter");
      return res.send(`
        <script>
                window.opener?.postMessage({
                    type: 'esewaPaymentComplete',
                    success: false,
                    message: 'Missing payment data'
                }, '${FRONTEND_ORIGIN}');
                window.close(); // Closes the eSewa popup/redirect window
        </script>
      `);
    }

    try {
        // Decode eSewa response
        const decodedData = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
        const { transaction_code, status, total_amount, transaction_uuid } = decodedData;

        // Verify payment with eSewa API
        const isVerified = await verifyEsewaPayment({
            oid: transaction_uuid,
            amt: total_amount,
            refId: transaction_code
        });

        // Update payment record in your DB
        const updateData = {
            status: isVerified && status === "COMPLETE" ? "completed" : "failed",
            transactionId: transaction_code,
            esewaResponse: decodedData,
            updatedAt: Date.now()
        };

        // You're correctly using paymentId or transaction_uuid to find the record
        const updatedPayment = await Payment.findByIdAndUpdate(
            paymentId || transaction_uuid,
            updateData,
            { new: true }
        );

        if (!updatedPayment) {
            throw new Error("Payment record not found");
        }

        // Send response to close popup and notify frontend
    res.send(`
      <script>
                window.opener?.postMessage({
          type: 'esewaPaymentComplete',
                    success: ${isVerified && status === "COMPLETE"},
                    paymentId: '${updatedPayment._id}',
                    transactionId: '${transaction_code}',
                    orderReference: '${updatedPayment.orderReference}'
                }, '${FRONTEND_ORIGIN}');
                window.close(); // Closes the eSewa popup/redirect window
      </script>
    `);

    } catch (error) {
        console.error("Verification error:", error);
    res.send(`
      <script>
                window.opener?.postMessage({
          type: 'esewaPaymentComplete',
          success: false,
                    message: 'Payment processing error'
                }, '${FRONTEND_ORIGIN}');
                window.close(); // Closes the eSewa popup/redirect window
      </script>
    `);
  }
});

router.get('/status/:orderId', async (req, res) => {
  try {
    const order = await Order.findOne({ tempOrderId: req.params.orderId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ payment_status: order.paymentStatus });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


router.post('/', async (req, res) => {
  try {
    const payment = new Payment({
      transactionId: `temp_${Date.now()}`,
      amount: req.body.amount,
      paymentMethod: req.body.paymentMethod,
      status: req.body.status || 'pending',
      orderReference: req.body.orderReference,
      user: req.user._id // From auth middleware
    });
    
    await payment.save();
    res.status(201).json(payment);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.get('/:id/status', async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json({ status: payment.status });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;