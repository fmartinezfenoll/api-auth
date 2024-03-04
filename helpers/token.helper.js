"use strict";
const jwt = require("jwt-simple");
const moment = require("moment");
const SECRET = require("../config").SECRET;
const EXP_TIME = require("../config").TOKEN_EXP_TIME;
// Devuelve un token tipo JSON Web Token
// Formato JWT:
// HEADER.PAYLOAD.VERIFY_SIGNATURE
//
// Donde:
// HEADER ( Objeto JSON con Algoritmo y tipo de token, codificado en formato base64Url ):
// {
// "typ": "JWT",
// "alg": "HS256"
// }.base64UrlEncode()
// PAYLOAD (Objeto JSON con lo que deseamos guardar, codificado en formato base64Url):
// {
// "sub": "56789123456789",
// "iat": 1603211718,
// "exp": 1604424918
// }.base64UrlEncode()
// VERIFY SIGNATURE:
// HMACSHA256 ( base64UrlEncode(HEADER) + "." + base64UrlEncode(PAYLOAD), SECRET )
//
function creaToken(user) {
  const payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(EXP_TIME, "minutes").unix(),
  };
  // console.log( { payload: payload });
  return jwt.encode(payload, SECRET);
}
function decodificaToken(token) {
  return new Promise((resolve, reject) => {
    try {
      const payload = jwt.decode(token, SECRET, false); // Marcamos false para que verifique firma y caducidad
      if (!payload.exp || payload.exp <= moment().unix()) {
        reject({ status: 401, message: "El token ha expirado" });
      }
      resolve(payload.sub); // Si todo ha ido bien, devolvemos el id del usuario
    } catch (err) {
      reject({
        status: 401,
        message: err.msg,
      });
    }
  });
}
module.exports = {
  creaToken,
  decodificaToken,
};
