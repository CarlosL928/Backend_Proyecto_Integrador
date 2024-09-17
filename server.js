const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { error } = require('console');
const { type } = require('os');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const cors = require('cors');

mongoose.connect('mongodb://localhost:27017/consultorio')
    .then(() => console.log('Conectado a MongoDB'))
    .catch((err) => console.log('Error al conectar a MongoDB', err));

//Datos a almacenar en la base de datos
const pacienteSchema = new mongoose.Schema({
    documento: { type: String, unique: true, required: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    edad: { type: Number, required: true },
    telefono: { type: String, required: true },
    historiaClinica: { type: String, required: true },
});

// Definición del esquema de Admin
const adminSchema = new mongoose.Schema({
    usuario: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const Paciente = mongoose.model('Paciente', pacienteSchema);
const Admin = mongoose.model('Admin', adminSchema);

app.use(cors());
app.use(express.json());

// Middleware de autenticación con el token
const authMiddleware = async (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
        return res.status(401).send({ error: 'Acceso denegado' });
    }
    const token = authHeader.replace('Bearer ', '');
    if (!token) {
        return res.status(401).send({ error: 'Acceso denegado' });
    }
    try {
        const verificar = jwt.verify(token, 'secretkey');
        req.user = verificar;
        next();
    } catch (error) {
        res.status(400).send({ error: 'Token no valido' });
    }
};

// Ruta para obtener todos los pacientes
app.get('/pacientes', authMiddleware, async (req, res) => {
    const pacientes = await Paciente.find();
    res.send(pacientes);
});

// Ruta para crear o verificar si el paciente existe.
app.post('/pacientes', authMiddleware, async (req, res) => {
    try {
        // Verificar si el paciente existe.
        const pacienteExistente = await Paciente.findOne({ documento: req.body.documento });
        if (pacienteExistente) {
            return res.status(400).send({ error: 'Paciente existente' });
        }

        // Crear un nuevo paciente
        const paciente = new Paciente(req.body);
        await paciente.save();
        res.send(paciente);
    } catch (error) {
        res.status(500).send({ error: 'Error al crear el paciente' });
    }
});

// Ruta para actualizar paciente por documento 
app.put('/pacientes/:documento', authMiddleware, async (req, res) => {
    const paciente = await Paciente.findOneAndUpdate(
        { documento: req.params.documento },
        req.body,
        { new: true }
    );
    res.send(paciente);
});

// Eliminar paciente por documento 
app.delete('/pacientes/:documento', authMiddleware, async (req, res) => {
    await Paciente.findOneAndDelete({ documento: req.params.documento });
    res.send({ message: 'Paciente eliminado' });
});

// Registrar un nuevo admin
app.post('/admin/register', async (req, res) => {
    const { usuario, password } = req.body;
    const existingAdmin = await Admin.findOne({ usuario });
    if (existingAdmin) {
        return res.status(400).send({ error: 'El usuario ya existe' });
    }
    const cifpassword = await bcrypt.hash(password, 10);
    const admin = new Admin({ usuario, password: cifpassword });
    await admin.save();
    res.send({ message: 'Admin creado' });
});

// Login de admin
app.post('/admin/login', async (req, res) => {
    const { usuario, password } = req.body;
    const admin = await Admin.findOne({ usuario });
    if (!admin) {
        return res.status(400).send({ error: 'Usuario no encontrado' });
    }
    const cifpassword = await bcrypt.compare(password, admin.password);
    if (!cifpassword) {
        return res.status(400).send({ error: 'Contraseña incorrecta' });
    }
    const token = jwt.sign({ id: admin._id }, 'secretkey');
    res.send({ token });
});

// conexion de socket.io que no me esta funcionando
io.on('connection', (socket) => {
    console.log('Usuario conectado');
    socket.on('llamarPaciente', (data) => {
        io.emit('llamarPaciente', data);
    });
});

// Iniciar el servidor
server.listen(3000, () => {
    console.log('Servidor en puerto 3000');
});