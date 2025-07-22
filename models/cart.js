const mongoose = require("mongoose");

const cartSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: true,
  },
  items: [
    {
      creationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "creations",
        required: true,
      },
    },
  ],
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Cart = mongoose.model("cart", cartSchema);
module.exports = Cart;