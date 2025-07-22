const mongoose = require("mongoose");
const Creation = require("../models/creation");
const Cart = require("../models/cart");

const addToCart = async (req, res) => {
  const userId = req.user.userId;
  const { creationId } = req.body;

  // console.log("Received creationId:", creationId);

  try {
    // Validate creationId
    if (!creationId) {
      return res.status(400).json({ message: "Missing creationId" });
    }

    let validCreationId;
    try {
      validCreationId = new mongoose.Types.ObjectId(creationId);
    } catch (err) {
      return res.status(400).json({ message: "Invalid creationId format" });
    }

    // Check if the item exists and is for sale
    const creation = await Creation.findById(validCreationId);
    if (!creation || !creation.forSale) {
      return res.status(404).json({ message: "Item not available for sale" });
    }

    // Find or create cart
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({
        userId,
        items: [],
      });
    }

    // Check if item already exists
    const itemExists = cart.items.some(item =>
      item.creationId?.toString() === validCreationId.toString()
    );

    if (itemExists) {
      return res.status(409).json({ message: "Item already in cart" });
    }

    // Add item to cart
    cart.items.push({ creationId: validCreationId });
    cart.updatedAt = new Date();
    await cart.save();

    res.status(200).json({ message: "Item added to cart", cart });
  } catch (err) {
    console.error("Error adding to cart:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

const getCart = async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.user.userId })
      .populate({
        path: "items.creationId",
        select: "title price creationPicture forSale creation_id userId",
        populate: {
          path: "userId",
          select: "fullName", // This gets the artist name
        },
      })

    if (!cart) return res.status(200).json({ items: [] });
    // console.log("daksdnjadjaks",cart);

    res.status(200).json(cart);
  } catch (err) {
    console.error("Error fetching cart:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

const removeFromCart = async (req, res) => {
  const userId = req.user.userId; 
  const { creationId } = req.body; 

  try {
    let validCreationId;
    try {
      // Validate that creationId is a valid MongoDB ObjectId
      validCreationId = new mongoose.Types.ObjectId(creationId);
    } catch (error) {
      // If not a valid ObjectId, return a 400 Bad Request
      return res.status(400).json({ message: "Invalid creationId format" });
    }

    const updatedCart = await Cart.findOneAndUpdate(
      { userId: userId },
      {
        $pull: { items: { creationId: validCreationId } },
        $set: { updatedAt: new Date() }
      },
      { new: true }
    );

    // If updatedCart is null, it means no cart was found for the given userId
    if (!updatedCart) {
      return res.status(404).json({ message: "Cart not found." });
    }

    res.status(200).json({ message: "Item removed from cart successfully", cart: updatedCart });

  } catch (err) {
    // Catch any server-side or database errors
    console.error("Error removing from cart:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// controllers/cart_controller.js
const addMultipleToCart = async (req, res) => {
  const userId = req.user.userId;
  const { items } = req.body; // Expecting array of creationIds

  try {
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({
        userId,
        items: [],
      });
    }

    // Filter out items already in cart
    const newItems = items.filter(creationId => 
      !cart.items.some(item => 
        item.creationId?.toString() === creationId.toString()
      )
    );

    // Add new items to cart
    newItems.forEach(creationId => {
      cart.items.push({ creationId });
    });

    cart.updatedAt = new Date();
    await cart.save();

    res.status(200).json({ message: "Items added to cart", cart });
  } catch (err) {
    console.error("Error adding items to cart:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

const getCartItemCount = async (req, res) => {
  const userId = req.user._id; // Assuming you are using verifyJWT middleware

  try {
    const cart = await Cart.findOne({ userId });

    if (!cart) {
      return res.status(200).json({ count: 0 });
    }

    return res.status(200).json({ count: cart.items.length });
  } catch (err) {
    console.error("Error fetching cart count:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

// In your backend cart controller
const clearCart = async (req, res) => {
  const userId = req.user.userId;

  try {
    const updatedCart = await Cart.findOneAndUpdate(
      { userId: userId },
      { 
        $set: { 
          items: [], // Empty the items array
          updatedAt: new Date() 
        } 
      },
      { new: true }
    );

    if (!updatedCart) {
      return res.status(404).json({ message: "Cart not found." });
    }

    res.status(200).json({ 
      message: "Cart cleared successfully", 
      cart: updatedCart 
    });

  } catch (err) {
    console.error("Error clearing cart:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// Add to your exports
module.exports = { addToCart, getCart, removeFromCart, addMultipleToCart, getCartItemCount, clearCart };