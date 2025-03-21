const jwt = require('jsonwebtoken');
const { UnauthorizedError } = require('../utils/errors');
const BlacklistToken = require('../models/BlacklistToken');

const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Acceso denegado. Token no proporcionado.' });
  }

  try {
    // Verificar si el token está en la lista negra
    const tokenInBlacklist = await BlacklistToken.findOne({ where: { token } });

    if (tokenInBlacklist) {
      return res.status(401).json({ success: false, message: 'Token inválido. Inicia sesión nuevamente.' });
    }

    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Token inválido o expirado.' });
  }
};

module.exports = authMiddleware;
