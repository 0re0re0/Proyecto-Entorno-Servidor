// ==========================================
// Importación de módulos y configuración inicial
// ==========================================
require('dotenv').config();
const paypal = require('@paypal/checkout-server-sdk');
const express = require('express');
const path = require('path'); // Para manejar rutas de archivos
const morgan = require('morgan'); // Middleware para logging
const fs = require('fs'); // Sistema de archivos
const mongoose = require('mongoose'); // ORM para MongoDB
const app = express(); // Inicializa la aplicación Express
const PORT = 3000; // Puerto en el que se ejecutará el servidor
const Activity = require('./models/Activity');
const multer = require('multer');
const User = require('./models/user')
const MongoStore = require('connect-mongo');
const Blog = require('./models/Blog');
const Producto = require('./models/Producto');

// ==========================================
// Middleware para análisis de datos de formularios
// ==========================================
app.use(express.urlencoded({ extended: true }));


// ==========================================
// Configuración de Passport para autenticación
// ==========================================
const passport = require('passport'); // para autenticar
const LocalStrategy = require('passport-local').Strategy; //para que sea estrategia local 
const session = require('express-session') // para coockies y manejo de sesiones
const bcrypt = require('bcrypt'); // para encriptar contraseñas
const flash = require('connect-flash');// para enviar mensajes flash al navegador
const Environment = paypal.core.SandboxEnvironment;
const paypalClient = new paypal.core.PayPalHttpClient(new Environment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
));


passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ email }); // Buscar usuario por email
    if (!user) {
      // Si no se encuentra el usuario, registra el intento fallido sin userId
      await Activity.create({
        userId: null,
        lastLogin: null,
        failedAttempts: 1,
        isLoggedIn: false
      });
      return done(null, false, { message: 'Usuario no encontrado' });
    }

    const isMatch = await bcrypt.compare(password, user.password); // Compara las contraseñas
    if (!isMatch) {
      // Incrementa los intentos fallidos en la actividad del usuario
      let activity = await Activity.findOne({ userId: user._id });
      if (activity) {
        activity.failedAttempts += 1;
        await activity.save();
      } else {
        await Activity.create({
          userId: user._id,
          lastLogin: null,
          failedAttempts: 1,
          isLoggedIn: false
        });
      }
      return done(null, false, { message: 'Contraseña incorrecta' });
    }

    // Si las credenciales son correctas, maneja el estado de sesión
    // Desactiva `isLoggedIn` para todos los demás usuarios
    await Activity.updateMany({}, { $set: { isLoggedIn: false } });

    // Actualiza o crea la actividad para el usuario actual
    let activity = await Activity.findOne({ userId: user._id });
    if (activity) {
      activity.lastLogin = Date.now();
      activity.isLoggedIn = true;
      await activity.save();
    } else {
      await Activity.create({
        userId: user._id,
        lastLogin: Date.now(),
        failedAttempts: 0,
        isLoggedIn: true
      });
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

// serializacion del usuario, guarda una ID para poder meternos
// y poder acceder a la  info del usuario solo manejando la ID
passport.serializeUser ((user,done) =>{
  done (null, user.id);
})
// deserializacion del usuario, con el ID, lo utiliza para obtener toda la INFO del usuario
//es mas seguro que usar todos los datos
passport.deserializeUser ((async(id,done) =>{
  try{
    const user = await User.findById(id)
    done (null,user)
  } catch (error){
    done(error)
  }
}))



// ==========================================
// Middleware para manejar actividad de usuarios
// ==========================================
const updateActivity = async (req, res, next) => {
  if (req.session.userId) {
    try {
      let activity = await Activity.findOne({ userId: req.session.userId });
      if (activity) {
        activity.lastLogin = Date.now();
        activity.isLoggedIn = true;
        await activity.save();
        console.log('Actividad actualizada');
      } else {
        const newActivity = await Activity.create({
          userId: req.session.userId,
          lastLogin: Date.now(),
          isLoggedIn: true
        });
        console.log('Nueva actividad creada:');
      }
    } catch (err) {
      console.error('Error al actualizar actividad:');
    }
  } else {
    console.log('No se encontró userId en la sesión.');
  }
  next();
};

// En el controlador



// ==========================================
// Middleware para sesiones y variables globales
// ==========================================

// Middleware para hacer `user` disponible en todas las vistas
app.use((req, res, next) => {
  res.locals.user = req.user || null; // Si no hay usuario, pasamos `null`
  next();
});

//middleware para cookies
app.use(session({
  secret: require('crypto').randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    maxAge: 1000*60*30
  }
}));

// inicializamos passport, session y flash
app.use(passport.initialize());
app.use(passport.session());

app.use(flash())
app.use((req,res,next)=>{
  res.locals.message=req.flash();
  next();
})
//manejar la proteccion de rutas, usado luego en app.get('/basededatos')
//verifica si hay sesion activa y valida
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).render('errorAuth', { title: 'No autenticado', message: 'Debes iniciar sesión para acceder' });
}



// ==========================================
// Configuración de conexión a MongoDB
// ==========================================

// Configuración de conexión a la base de datos MongoDB
const dbURI = process.env.MONGODB_URI;

// Configuración para guardar logs de acceso
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });

// Conexión a MongoDB
mongoose
  .connect(dbURI)
  .then(() => app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`)))
  .catch((error) => console.log('Error de conexión a la BBDD:', error));


// ==========================================
// Configuración del motor de vistas y archivos estáticos
// ==========================================

// Configuración del motor de plantillas EJS
app.set('view engine', 'ejs'); // Utilizar EJS para renderizar vistas
app.set('views', path.join(__dirname, 'vistas')); // Definir la carpeta para las vistas
// Middleware para servir archivos estáticos (CSS, imágenes, etc.)
app.use(express.static('public'));
app.use('/uploads', express.static('uploads')) //
// Middleware para logging de cada solicitud HTTP usando 'morgan'
app.use(morgan('dev', { stream: accessLogStream }));

// ==========================================
// Configuración para subir archivos con Multer
// ==========================================

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, 'public', 'uploads')); // Asegúrate de usar una ruta válida
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname); // Obtén la extensión del archivo
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9); // Genera un sufijo único
    cb(null, `${uniqueSuffix}${ext}`); // Construye el nombre del archivo
  }
});
const upload = multer({ storage });

// ==========================================
// Rutas de la aplicación
// ==========================================

// Ruta de la página de inicio (Home)
app.get('/', (req, res) => {
  res.render('main2', { 
    user: req.user, 
    title: 'Bienvenido a la plataforma' // Define el título aquí
  });
});

app.get('/about-me', (req, res) => {  // Ruta para redirigir '/about-me' a '/about'
  res.redirect('/about');
});


app.get('/sign-up',(req, res) => {
  res.render('sign-up', { title: 'Crear cuenta' });  // Ruta para crear cuenta
})
// Ruta para manejar el registro
app.post('/sign-up', upload.single('profilePic'), async (req, res) => {
  try {
    const { email, password, name, surname, dob, gender } = req.body;

    if (!password) {
      return res.status(400).send('La contraseña es requerida');
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('El usuario ya existe');
    }

    const newUser = new User({
      email,
      password,
      name,
      surname,
      dob,
      gender,
      profilePic: req.file ? `/uploads/${req.file.filename}` : null
    });

    await newUser.save();

    // Crear actividad inicial
    await Activity.create({
      userId: newUser._id,
      lastLogin: Date.now(),
      failedAttempts: 0,
      isLoggedIn: false
    });

    res.redirect('/login');
  } catch (error) {
    console.log(error);
    res.status(500).send('Error al crear el usuario');
  }
});


app.get('/login',(req, res) => {
  res.render('login', { title: 'Iniciar sesion' }); // Ruta para iniciar sesion
})

app.post('/login', passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: true
}), async (req, res) => {
  req.session.userId = req.user._id;
  await updateActivity(req, res, () => {});
  res.redirect('/basededatos');
});

app.get('/user-activity', (req, res) => {
  
  Activity.find()
    .populate('userId') // Para traer la información de usuario
    .then(activities => {
      // Asegúrate de pasar activities a la vista
      res.render('basededatos', { activities });
    })
    .catch(err => console.error(err));
});

app.get('/basededatos', ensureAuthenticated, async (req, res) => {
  try {
    const users = await User.find(); // Obtén los usuarios
    const activities = await Activity.find().populate('userId'); // Obtén las actividades también
    console.log('Actividades obtenidas'); // Verifica qué datos se están obteniendo

    res.render('basededatos', { 
      title: 'Base de Datos de Usuarios',
      user: req.user,
      users,
      activities:activities || [] // Asegúrate de pasar activities aquí
    });
  } catch (error) {
    res.status(500).send('Error al cargar los usuarios');
  }
});

app.get ('/logout',(req, res)=>{
  req.logout((error)=>{
    if(error){
      console.log(error)
      return res.status(500).send('error al cerrar sesion')
    }
    res.redirect('/')
  })
})

// Ruta para mostrar el formulario de edición
app.get('/edit-user/:id', async (req, res) => {
  try {
      const user = await User.findById(req.params.id);
      if (!user) {
          return res.status(404).send('Usuario no encontrado');
      }
      res.render('edit-user', { user, title: 'Editar Usuario' }); // Pasa el valor de 'title'
  } catch (error) {
      console.error(error);
      res.status(500).send('Error al cargar el formulario de edición');
  }
});

// Get all blogs
app.get('/blogs', async (req, res) => {
  try {
    const blogs = await Blog.find().populate('author', 'name');
    res.render('blogs', { 
      title: 'Blogs', 
      blogs,
      user: req.user // Asegúrate de pasar el usuario
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al cargar los blogs');
  }
});

// Create blog form
app.get('/create-blog', ensureAuthenticated, (req, res) => {
  res.render('create-blog', { title: 'Crear Blog', blog: null });
});

// Get donations page
app.get('/donaciones', async (req, res) => {
  try {
      const productos = await Producto.find();
      res.render('donaciones', { 
          title: 'Donaciones',
          user: req.user,
          productos,
          process: { env: { PAYPAL_CLIENT_ID: process.env.PAYPAL_CLIENT_ID } }
      });
  } catch (error) {
      console.error(error);
      res.status(500).send('Error al cargar las donaciones');
  }
});

// Create blog
app.post('/create-blog', ensureAuthenticated, upload.single('image'), async (req, res) => {
  try {
    const { title, summary, content } = req.body;
    const blog = new Blog({
      title,
      summary,
      content,
      author: req.user._id,
      image: req.file ? `/uploads/${req.file.filename}` : null
    });
    await blog.save();
    res.redirect('/blogs');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al crear el blog');
  }
});

// Edit blog form
app.get('/edit-blog/:id', ensureAuthenticated, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).send('Blog no encontrado');
    }
    if (blog.author.toString() !== req.user._id.toString()) {
      return res.status(403).send('No autorizado');
    }
    res.render('create-blog', { title: 'Editar Blog', blog });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al cargar el blog');
  }
});

// Update blog
app.post('/edit-blog/:id', ensureAuthenticated, upload.single('image'), async (req, res) => {
  try {
    const { title, summary, content } = req.body;
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).send('Blog no encontrado');
    }
    if (blog.author.toString() !== req.user._id.toString()) {
      return res.status(403).send('No autorizado');
    }
    
    blog.title = title;
    blog.summary = summary;
    blog.content = content;
    blog.updatedAt = Date.now();
    if (req.file) {
      blog.image = `/uploads/${req.file.filename}`;
    }
    
    await blog.save();
    res.redirect('/blogs');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al actualizar el blog');
  }
});

// Delete blog
app.post('/delete-blog/:id', ensureAuthenticated, async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).send('Blog no encontrado');
    }
    if (blog.author.toString() !== req.user._id.toString()) {
      return res.status(403).send('No autorizado');
    }
    await blog.deleteOne();
    res.redirect('/blogs');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al eliminar el blog');
  }
});

app.post('/edit-user/:id', upload.single('profilePic'), async (req, res) => {
  try {
    const { name, surname, email, dob, gender } = req.body;

    // Construir el objeto de actualización
    const updateFields = {};
    if (name) updateFields.name = name;
    if (surname) updateFields.surname = surname;
    if (email) updateFields.email = email;
    if (dob) updateFields.dob = new Date(dob);
    if (gender) updateFields.gender = gender;

    // Manejar la nueva foto de perfil si se sube
    if (req.file) {
      updateFields.profilePic = `/uploads/${req.file.filename}`;
    }

    // Actualizar el usuario
    const updatedUser = await User.findByIdAndUpdate(req.params.id, updateFields, { new: true });

    if (!updatedUser) {
      return res.status(404).send('Usuario no encontrado.');
    }

    res.redirect('/basededatos');
  } catch (error) {
    console.error('Error al actualizar el usuario:', error);
    res.status(500).send('Error al actualizar el usuario.');
  }
});

// Ruta para eliminar un usuario
app.post('/delete-user/:id', async (req, res) => {
  try {
    // Elimina el usuario de la base de datos
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).send('Usuario no encontrado');
    }

    // Elimina también los registros de actividad relacionados con el usuario
    await Activity.deleteMany({ userId: user._id });

    res.redirect('/basededatos');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al eliminar el usuario');
  }
});

// Añade estas rutas para manejar las órdenes de PayPal
app.post('/api/orders', async (req, res) => {
  try {
      const { amount } = req.body;
      const order = await paypalClient.execute(
          new paypal.orders.OrdersCreateRequest()
              .requestBody({
                  intent: 'CAPTURE',
                  purchase_units: [{
                      amount: {
                          currency_code: 'EUR',
                          value: amount
                      }
                  }]
              })
      );
      res.json({ id: order.result.id });
  } catch (error) {
      console.error('Error al crear orden:', error);
      res.status(500).json({ error: 'Error al crear la orden' });
  }
});

app.post('/api/orders/:orderID/capture', async (req, res) => {
  try {
      const { orderID } = req.params;
      const captureOrder = await paypalClient.execute(
          new paypal.orders.OrdersCaptureRequest(orderID)
      );
      res.json(captureOrder.result);
  } catch (error) {
      console.error('Error al capturar orden:', error);
      res.status(500).json({ error: 'Error al capturar la orden' });
  }
});


app.get('/error', (req, res) => {
  res.render('errorAuth', { 
    title: 'Error de autenticación', 
    user: req.user // Asegúrate de pasar `req.user` si estás usando sesiones o Passport.js
  });
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'Página no encontrada' }); // Middleware para manejar errores 404 (Página no encontrada)
});
const bodyParser = require('body-parser');






