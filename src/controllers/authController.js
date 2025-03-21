const authSchemas = require("../schema/authSchemas.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Usuario = require("../models/usuario.js");
const dotenv = require("dotenv");
const { UnauthorizedError } = require("../utils/errors");
const BlacklistToken = require("../models/BlacklistToken"); // Asegúrate de crear este modelo

dotenv.config();

// 🔹 REGISTRO DE USUARIO
const register = async (req, res) => {
  try {
    console.log("Datos recibidos:", req.body); // Para debugging
    
    // Validar con Zod
    const { nombre, identificacion, correoElectronico, contrasena, RolID } = 
      authSchemas.registerSchema.parse(req.body);
    
    // Verificar si el usuario ya existe
    const usuarioExistente = await Usuario.findOne({ 
      where: { CorreoElectronico: correoElectronico } 
    });
    
    if (usuarioExistente) {
      return res.status(400).json({ error: "El correo ya está registrado" });
    }
    
    // Hashear la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(contrasena, salt);
    
    // Crear el usuario en la base de datos
    const nuevoUsuario = await Usuario.create({
      Nombre: nombre,
      Identificacion: identificacion,
      CorreoElectronico: correoElectronico,
      Contrasena: hashedPassword,
      RolID: RolID,
    });
    
    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    console.error("Error completo:", error);
    
    if (error.name === "ZodError") {
      return res.status(400).json({ 
        error: "Datos de registro inválidos", 
        detalles: error.errors 
      });
    }
    
    res.status(500).json({ 
      mensaje: "Error en el registro", 
      error: error.message 
    });
  }
};

// 🔹 LOGIN DE USUARIO
const login = async (req, res) => {
  try {
    // Validar los datos con Zod
    const { correoElectronico, contrasena } = 
      authSchemas.loginSchema.parse(req.body);
    
    // Buscar usuario en la base de datos
    const usuario = await Usuario.findOne({ 
      where: { CorreoElectronico: correoElectronico } 
    });
    
    if (!usuario) {
      return res.status(401).json({ error: "Credenciales incorrectas" });
    }
    
    // Verificar la contraseña
    const contrasenaValida = await bcrypt.compare(contrasena, usuario.Contrasena);
    if (!contrasenaValida) {
      return res.status(401).json({ error: "Credenciales incorrectas" });
    }
    
    // Generar token JWT
    const token = jwt.sign(
      { id: usuario.IDUsuario, rol: usuario.RolID },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );
    
    res.json({ token, rol: usuario.RolID });
  } catch (error) {
    console.error("Error en login:", error);
    
    if (error.name === "ZodError") {
      return res.status(400).json({ 
        error: "Datos de inicio de sesión inválidos", 
        detalles: error.errors 
      });
    }
    
    res.status(500).json({ error: "Error en el servidor" });
  }
};

// 🔹 OBTENER PERFIL
const getProfile = async (req, res) => {
  try {
    const userId = req.usuario.id;
    const user = await Usuario.findByPk(userId, {
      attributes: ["IDUsuario", "Nombre", "CorreoElectronico", "RolID"],
    });

    if (!user) {
      throw new UnauthorizedError("Usuario no encontrado");
    }

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error al obtener perfil", error });
  }
};

// 🔹 CERRAR SESIÓN (LOGOUT)
const logout = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      throw new UnauthorizedError("Token no proporcionado");
    }

    // Guardar el token en la lista negra
    await BlacklistToken.create({ token });

    res.json({ success: true, message: "Sesión cerrada correctamente" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error al cerrar sesión", error });
  }
};

module.exports = { register, login, getProfile, logout };