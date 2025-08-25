const express = require('express');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

// Configuração da Estratégia do Passport para o Google
passport.use(new GoogleStrategy({
    clientID: '874634983574-h6tooa1ekuh9ue16a5hjdri73csudgo4.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // Aqui você pode salvar o perfil do usuário no seu banco de dados
    return done(null, profile);
  }
));

// Configuração da sessão do Express
app.use(session({
    secret: 'sua-chave-secreta-para-sessao',
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// Rota de login com o Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// Rota de callback do Google
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/minha-conta.html' }),
  (req, res) => {
    // Autenticação bem-sucedida, redirecione para a página inicial
    res.redirect('/');
  });

// Rota para logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Serve os arquivos estáticos da pasta 'client'
app.use(express.static(path.join(__dirname, '..', 'website')));

// Rota para verificar se o usuário está logado e obter as informações de perfil
app.get('/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            isLoggedIn: true,
            displayName: req.user.displayName,
            photo: req.user.photos[0].value,
        });
    } else {
        res.json({ isLoggedIn: false });
    }
});

// Inicia o servidor e verifica por erros
app.listen(port, (err) => {
    if (err) {
        return console.log('Algo deu errado:', err);
    }
    console.log(`Servidor rodando em http://localhost:${port}`);
});

// A serialização e desserialização do usuário é necessária para a sessão do Passport
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});