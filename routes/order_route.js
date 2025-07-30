const express = require('express');
const router = express.Router();
const { saveOrder, getOrderById, getMyOrdersController } = require('../controllers/order_controller');
const { verifyJWT } = require('../controllers/creation_controller');


// POST /api/orders
// Apply the verifyJWT middleware here
router.post('/', verifyJWT, saveOrder);
router.get('/my', verifyJWT, getMyOrdersController);
router.get('/:id', verifyJWT, getOrderById);  // ✅ Added missing JWT middleware!


module.exports = router;