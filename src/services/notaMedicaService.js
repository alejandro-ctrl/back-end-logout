const { NotaMedica } = require('../models/notaMedica.js');

const createNotaMedica = async (titulo, pacienteId, autorId, contenido, imagen) => {
  const notaMedica = await NotaMedica.create({
    Titulo: titulo,
    PacienteID: pacienteId,
    AutorID: autorId,
    Contenido: contenido,
    Imagen: imagen,
  });

  return notaMedica;
};

const getNotasMedicasByPaciente = async (pacienteId) => {
  const notasMedicas = await NotaMedica.findAll({
    where: { PacienteID: pacienteId },
    include: [{ model: Usuario, as: 'Autor', attributes: ['Nombre'] }],
    order: [['FechaHora', 'DESC']],
  });

  return notasMedicas;
};

module.exports = { createNotaMedica, getNotasMedicasByPaciente };