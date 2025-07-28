const Creation = require('../models/creation');
const Notification = require('../models/notification');
const Order = require('../models/order');
const AuditLogger = require('../services/audit_logger');
const mongoose = require('mongoose'); 

// POST /api/orders
const saveOrder = async (req, res) => { 
    try {
    console.log('[CONTROLLER] Request user:', req.user);
    console.log('[CONTROLLER] Request body:', req.body);
    console.log('[CONTROLLER] Payment method:', req.body.paymentMethod);
    console.log('[CONTROLLER] Payment status from frontend:', req.body.paymentStatus);
        const userId = req.user.userId;

        const {
            items,
            deliveryOption,
            paymentMethod,
            paymentStatus, // Add this to extract paymentStatus from frontend
            totalAmount,
            subtotal,
            taxAmount,
            deliveryCharge,
            shippingAddress,
            customerEmail, // Still useful for confirmation emails
            customerPhone // Still useful for confirmation
        } = req.body;

        // Basic validation
        if (!items || items.length === 0 || !deliveryOption || !paymentMethod || !totalAmount) {
            return res.status(400).json({ message: 'Missing required order details.' });
        }

        // Map frontend cart items to backend order item schema
        const orderItems = items.map(item => ({
            creationId: new mongoose.Types.ObjectId(item._id), // Convert string ID to ObjectId
            title: item.title,
            quantity: item.quantity || 1,
            price: item.price,
            creationPicture: item.image
        }));

        // Dynamically set shipping address based on delivery option
        let finalShippingAddress;
        if (deliveryOption === 'local') {
            // Validate required fields for local delivery address
            if (!shippingAddress.street || !shippingAddress.city) {
                return res.status(400).json({ message: 'Full shipping address is required for local delivery.' });
            }
            finalShippingAddress = {
                street: shippingAddress.street,
                city: shippingAddress.city,
                district: shippingAddress.district,
                province: shippingAddress.province,
                zip: shippingAddress.zip, // Include zip if it's part of your model
            };
        } else { // pickup
            // For pickup, store placeholder address or mark as N/A
            finalShippingAddress = {
                street: 'N/A',
                city: 'Kathmandu',
                zip: 'N/A',
            };
        }

        // Log the payment details for debugging
        console.log('[ORDER] Creating order with payment details:', {
            paymentMethod,
            paymentStatus: paymentStatus || 'unpaid',
            totalAmount
        });

        const newOrder = new Order({
            user: userId,
            items: orderItems,
            totalAmount: totalAmount,
            subtotal: subtotal,
            taxAmount: taxAmount,
            deliveryCharge: deliveryCharge,
            shippingAddress: finalShippingAddress, 
            deliveryOption: deliveryOption === 'pickup' ? 'on-site pickup' : 'local delivery',
            paymentMethodUsed: paymentMethod,
            paymentStatus: paymentStatus || 'unpaid', // Use the paymentStatus from frontend with fallback
            orderStatus: 'pending',
            customerEmail: customerEmail,
            customerPhone: customerPhone,
        });

        const savedOrder = await newOrder.save();

        // Audit log order placement
        await AuditLogger.logOrderAction(
            { _id: userId, username: req.user.username, role: req.user.role },
            savedOrder.orderId,
            'order_placed',
            req.ip || req.connection.remoteAddress,
            req.headers['user-agent'],
            {
                totalAmount,
                paymentMethod,
                paymentStatus,
                deliveryOption,
                itemCount: items.length
            }
        );

        const creationIds = items.map(item => item._id); // assuming this is the custom creation_id
        const creations = await Creation.find(
        { _id: { $in: creationIds } },
        "userId creation_id"
        );
console.log("Found creations for notification:", creations);

        for (const creation of creations) {
            // Prevent sending notification to yourself (buyer == seller)
            if (creation.userId.toString() === userId) continue;

            await new Notification({
                type: "purchase",
                creation: creation._id,
                notification_for: creation.userId,
                user: userId, // The buyer
                order: savedOrder._id
            }).save();
        }

        res.status(201).json({
            message: 'Order placed successfully!',
            order: savedOrder,
            orderNumber: savedOrder.orderId
        });

    } catch (error) {
        console.error('Error placing order:', error);
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ message: messages.join(', ') });
        }
        res.status(500).json({ message: 'Internal server error. Could not place order.' });
    }
}

const getOrderById = async (req, res) => {
  try {
    const { id } = req.params;

    // Find by orderId field (custom string like ORD-...)
    const order = await Order.findOne({ orderId: id })
      .populate("user", "username email") // Populates the main order user
      .populate({ // Populate creationId and its nested userId for artist's name
        path: "items.creationId",
        select: "name description price images userId", // <-- Add userId here
        populate: {
          path: "userId",
          select: "fullName" // Get the fullName from the User model (who is the artist)
        }
      });

    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    res.status(200).json(order);
  } catch (error) {
    console.error("Error fetching order by ID:", error);
    res.status(500).json({ message: "Internal server error. Could not fetch order." });
  }
};

const getMyOrdersController = async (req, res) => {
  try {
    const userId = req.user.userId; // comes from your JWT verify middleware

    const orders = await Order.find({ user: userId })
      .sort({ createdAt: -1 })
      .populate("items.creationId", "title creation_id creationPicture price") // populates the creation reference
      .lean();

    res.json({ orders });
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ message: 'Failed to fetch orders' });
  }
};

module.exports = { saveOrder, getOrderById, getMyOrdersController };