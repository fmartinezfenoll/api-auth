"use strict";
// importaciones
const config = require("./config");
const logger = require("morgan");
const mongojs = require("mongojs");
const cors = require("cors");
const helmet = require("helmet");
var express = require("express");
var fs = require("fs");
var https = require("https");
var app = express();
const PassHelper = require("./helpers/pass.helper");
const TokenHelper = require("./helpers/token.helper");
// Declaraciones
const port = config.PORT;
const urlDB = config.DB;
const db = mongojs(urlDB); // Enlazamos con la DB
const id = mongojs.ObjectID; // Función para convertir un id textual en un objectID
const moment = require("moment");

// Declaraciones para CORS
var allowCrossTokenOrigin = (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // Permiso a cualquier URL. Mejor acotar
  return next();
};
var allowCrossTokenMethods = (req, res, next) => {
  res.header("Access-Control-Allow-Methods", "*"); // Mejor acotar (GET,PUT,POST,DELETE)
  return next();
};
var allowCrossTokenHeaders = (req, res, next) => {
  res.header("Access-Control-Allow-Headers", "*"); // Mejor acotar (Content-type)
  return next();
};
var auth = (req, res, next) => {
  // Comprobamos que han enviado el token tipo Bearer en el Header
  if (!req.headers.authorization) {
    return res.status(401).send({
      result: "KO",
      message:
        "Cabecera de autenticación tipo Bearer no encontrada [Authorization: Bearer jwtToken]",
    });
  }
  const token = req.headers.authorization.split(" ")[1]; // El formato es: Authorization: "Bearer JWT"
  // Comprobamos que han enviado el token
  if (!token) {
    return res.status(401).send({
      result: "KO",
      message:
        "Token de acceso JWT no encontrado dentro de la cabecera [Authorization: Bearer jwtToken]",
    });
  }
  // Verificamos que el token es correcto
  TokenHelper.decodificaToken(token)
    .then((userId) => {
      req.user = {
        id: userId,
        token: token,
      };
      return next();
    })
    .catch((response) => {
      res.status(response.status);
      res.json({
        result: "KO",
        message: response.message,
      });
    });
};

// middlewares
app.use(helmet());
app.use(logger("dev")); // probar con: tiny, short, dev, common, combined
app.use(express.urlencoded({ extended: false })); // parse application/x-www-form-urlencoded
app.use(express.json()); // parse application/json
app.use(cors()); // activamos CORS
app.use(allowCrossTokenOrigin); // configuramos origen permitido para CORS
app.use(allowCrossTokenMethods); // configuramos métodos permitidos para CORS
app.use(allowCrossTokenHeaders); // configuramos cabeceras permitidas para CORS

// routes
app.get("/api/user", auth, (req, res, next) => {
  db.user.find((err, users) => {
    if (err) return next(err);
    res.json(users);
  });
});
app.get("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.findOne({ _id: id(elementoId) }, (err, usuarioRecuperado) => {
    if (err) return next(err);
    res.json(usuarioRecuperado);
  });
});
app.post("/api/user", auth, (req, res, next) => {
  const nuevoElemento = req.body;
  db.user.save(nuevoElemento, (err, usuarioRecuperado) => {
    if (err) return next(err);
    res.json(usuarioRecuperado);
  });
});
app.put("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  const nuevosRegistros = req.body;
  db.user.update(
    { _id: id(elementoId) },
    { $set: nuevosRegistros },
    { safe: true, multi: false },
    (err, result) => {
      if (err) return next(err);
      res.json(result);
    }
  );
});
app.delete("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.remove({ _id: id(elementoId) }, (err, resultado) => {
    if (err) return next(err);
    res.json(resultado);
  });
});
//------------------------------------------------------------------------------
// GET
app.get("/api/auth", (req, res) => {
  db.user.find({}, { _id: 0, displayName: 1, email: 1 }, (err, users) => {
    if (err) {
      console.error("Error get", err);
    }
    res.json(users);
  });
});
app.get("/api/auth/me", auth, (req, res) => {
  const userId = req.user.id;
  db.user.find({ _id: id(userId) }, (err, users) => {
    if (err) {
      console.error("Error get", err);
    }
    res.json(users);
  });
});

//--------------------- -----------------------------------------
app.post("/api/auth/reg", (req, res) => {
  const { nombre, email, pass } = req.body;

  // Validación de datos
  if (!nombre || !email || !pass) {
    return res.status(400).json({
      result: "NO",
      msg: "Faltan datos obligatorios, datos : name, email, password",
    });
  }

  // Verificación de usuario existente
  db.user.findOne({ email }, (err, usuarioEncontrado) => {
    if (err)
      return res.status(500).json({
        result: "NO",
        msg: "Error servidor",
      });

    if (usuarioEncontrado)
      return res.status(409).json({
        result: "NO",
        msg: "Ya existe un usuario con ese email",
      });

    // Encriptación de password
    PassHelper.encriptaPassword(pass).then (hash => {
      // Creación del nuevo usuario
      const nuevoUsuario = {
        displayName: nombre,
        email: email,
        password: hash,
        signupDate: moment().unix(),
        lastLogin: moment().unix(),
      };
      
      // Guardado del usuario
      db.user.save(nuevoUsuario, (err, userGuardado) => {
        if (err) {
          res.status(500).json({
            result: "NO",
            msg: "Error servidor",
          });
        }
        // Generación del token
        const token = TokenHelper.creaToken(nuevoUsuario);
        res.json({result: 'OK', token, usuario: userGuardado});
      });
      
    });
    
  });
});
//----------------------------------------------------LOGIN
app.post("/api/auth", (req, res) => {
  const { nombre, email, pass } = req.body;

  // Validación de datos
  if (!email || !pass) {
    return res.status(400).json({
      result: "NO",
      msg: "Faltan datos obligatorios, datos : email, password",
    });
  }

  // Verificación de usuario existente
  db.user.findOne({ email }, (err, usuarioEncontrado) => {
    if (err)
      return res.status(500).json({
        result: "NO",
        msg: "Error servidor",
      });

    if (!usuarioEncontrado)
      return res.status(409).json({
        result: "NO",
        msg: "No existe ese correo",
      });

    // Compara contraseña
    PassHelper.comparaPassword(pass,usuarioEncontrado.password).then(passwordsMatch=>{
      if(!passwordsMatch){
        return res.status(401).json({
          result: "NO",
          msg: "Contraseña no coincide",
        });
      }
      //Actualiza datos de Login
      db.user.update({_id: usuarioEncontrado._id}, {$set:{lastLogin: moment().unix()}} ,(err, usuarioUpdated) => {
        if (err) {
          res.status(500).json({
            result: "NO",
            msg: "Error servidor",
          });
        }
        // Generación del token
        const token = TokenHelper.creaToken(usuarioEncontrado);
        res.json({result: 'OK', token, usuario: usuarioEncontrado});
      });
    });


  });
});
// Iniciamos la aplicación-----------------------------------------------------------------
https
  .createServer(
    {
      cert: fs.readFileSync("./cert/cert.pem"),
      key: fs.readFileSync("./cert/key.pem"),
    },
    app
  )
  .listen(port, function () {
    console.log(`API RESTful CRUD ejecutándose en https://localhost:${port}`);
  });
