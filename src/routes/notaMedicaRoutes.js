const express = require('express');
const { crearNotaMedica, obtenerNotasMedicas, actualizarNotaMedica } = require('../controllers/notaMedicaController.js');
const authMiddleware = require('../middlewares/authMiddleware');
const roleMiddleware = require('../middlewares/roleMiddleware');
const validationMiddleware = require('../middlewares/validationMiddleware');
const { validacionesCrearNotaMedica, validacionesObtenerNotasMedicas, validacionesActualizarNotaMedica } = require('../validators/notaMedicaValidations');
const validateSchema = require('../middlewares/validatore.schema.js')
const {NotaSchema} = require('../schema/notas.schema.js')


const router = express.Router();

// Crear una nueva nota médica
router.post(
  '/notas-medicas',
  validateSchema(NotaSchema),
  // authMiddleware,
  // roleMiddleware(['Acudiente', 'Empresa']),
  // validationMiddleware(validacionesCrearNotaMedica),
  crearNotaMedica
);

// Obtener notas médicas de un paciente
router.get(
  '/pacientes/:pacienteId/notas-medicas',
  authMiddleware,
  roleMiddleware(['Acudiente', 'Empresa']),
  validationMiddleware(validacionesObtenerNotasMedicas),
  obtenerNotasMedicas
);

// Actualizar una nota médica
router.put(
  '/notas-medicas/:notaId',
  authMiddleware,
  roleMiddleware(['Acudiente', 'Empresa']),
  validationMiddleware(validacionesActualizarNotaMedica),
  actualizarNotaMedica
);

module.exports = router;