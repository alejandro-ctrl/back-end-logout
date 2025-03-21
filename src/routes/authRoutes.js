const express = require('express');
const { login, register, getProfile, logout } = require('../controllers/authController');
const { validateLogin, validateRegister } = require('../validators/authValidations');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router();

router.post('/login', validateLogin, login);
router.post('/register', validateRegister, register);
router.get('/profile', authMiddleware, getProfile); // Obtener perfil
router.post('/logout', authMiddleware, logout); // Cerrar sesión

module.exports = router;