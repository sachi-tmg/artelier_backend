// models/order.js
const mongoose = require('mongoose');

// Define the schema for individual items within an order
const orderItemSchema = new mongoose.Schema({
    // Changed from productId to creationId, and ref to 'creations'
    creationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'creations', // This should match the model name you export for your creations
        required: true
    },
    title: { // Corresponds to 'title' in your Creation schema
        type: String,
        required: true
    },
    quantity: {
        type: Number,
        required: true,
        min: 1
    },
    price: { // Price at the time of order (from your Creation.price)
        type: Number, // Assuming you'll convert Creation.price (String) to Number when creating order
        required: true
    },
    creationPicture: { // Corresponds to 'creationPicture' in your Creation schema
        type: String // Store a snapshot of the image URL
    }
}, { _id: false }); // Do not create _id for subdocuments unless explicitly needed

// Define the main Order schema
const orderSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users', // Reference to your User model
        required: true
    },
    orderId: { // A user-friendly order number
        type: String,
        unique: true,
        required: true,
        default: () => `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`
    },
    items: [orderItemSchema], // Array of items purchased (each referencing a Creation)

    totalAmount: { // Total including delivery and tax
        type: Number,
        required: true
    },
    subtotal: { // Total of just items
        type: Number,
        required: true
    },
    taxAmount: {
        type: Number,
        default: 0
    },
    deliveryCharge: {
        type: Number,
        default: 0
    },

    shippingAddress: {
        street: { type: String, required: true },
        city: { type: String, required: true },
        zip: { type: String, required: true },
    },
    // Optional: billingAddress if different from shipping

    deliveryOption: {
        type: String,
        enum: ['on-site pickup', 'local delivery'],
        required: true
    },
    
    paymentMethodUsed: { // Redundant but good snapshot of what was chosen
        type: String,
        enum: ['esewa', 'card', 'cash'],
        required: true
    },
    paymentRef: { // Reference to the Payment document
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Payment'
    },

    paymentStatus: { // Financial status of the order (derived from payment)
        type: String,
        enum: ['unpaid', 'paid', 'partially_paid', 'refunded'],
        default: 'unpaid'
    },
    orderStatus: { // Fulfillment status of the order
        type: String,
        enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'completed'],
        default: 'pending' // Initial status
    },
    
    // Additional fields for delivery tracking etc.
    deliveryTrackingId: {
        type: String
    },
    deliveryDate: {
        type: Date
    },

    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

orderSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('Order', orderSchema);