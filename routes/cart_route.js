const express = require("express");
const router = express.Router();
const { verifyJWT } = require("../controllers/creation_controller"); 
const { addToCart, getCart, removeFromCart, addMultipleToCart, getCartItemCount, clearCart } = require("../controllers/cart_controller");

router.post("/add", verifyJWT, addToCart);
router.get("/", verifyJWT, getCart);
router.post("/remove", verifyJWT, removeFromCart);
router.post("/add-multiple", verifyJWT, addMultipleToCart);
router.get("/get-cart-count", verifyJWT, getCartItemCount);
router.delete('/clear', verifyJWT, clearCart);

module.exports = router;
