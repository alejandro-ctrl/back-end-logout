// src/server.js
require('dotenv').config(); // Cargar variables de entorno
const app = require('./app');
const sequelize = require('./config/db'); // Importar sequelize desde la configuración
const configureSocket = require('./config/socket');

const PORT = process.env.PORT || 3000;

// Verificar si sequelize está definido correctamente
if (!sequelize) {
  console.error('Error: La instancia de Sequelize no se cargó correctamente.');
  process.exit(1); // Finalizar la ejecución si la base de datos no está configurada
}

// Iniciar el servidor
const server = app.listen(PORT, async () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);

  try {
    await sequelize.authenticate(); // Verificar conexión a la base de datos
    await sequelize.sync(); // Sincronizar modelos con la base de datos
    console.log('Base de datos conectada correctamente');
  } catch (error) {
    console.error('Error al conectar la base de datos:', error);
    process.exit(1); // Finalizar si hay un error en la conexión
  }
});

// Configurar Socket.IO
const io = configureSocket(server);
app.set('io', io); // Hacer disponible `io` en toda la aplicación
console.log("DB_NAME:", process.env.DB_NAME);
module.exports = { app, server, io };
