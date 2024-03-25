module.exports = {
    PORT: process.env.PORT || 4100,
    DB: process.env.MONGODB || 'mongodb://localhost:27017/SD',
    TOKEN: 'password1234',
    SECRET: 'clavesecreta',
    TOKEN_EXP_TIME: 7 * 24 * 60
   } 