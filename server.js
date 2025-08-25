// Importa as bibliotecas necessárias
const express = require('express');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;

// Conexão com o MongoDB
const MONGODB_URI = 'mongodb+srv://stringflowstore:meAHcnUTJMU31A0F@stringflowstore.x4vhijf.mongodb.net/?retryWrites=true&w=majority&appName=StringFlowStore';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('--- Conectado ao MongoDB Atlas com sucesso! ---');
}).catch(err => {
    console.error('*** Erro de conexão com o MongoDB: ', err);
});

// Definir o Schema do Usuário
const userSchema = new mongoose.Schema({
    googleId: String,
    displayName: String,
    email: String,
    photo: String,
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
});

const User = mongoose.model('User', userSchema);

// Middleware de sessão e Passport - a ordem é crucial
app.use(session({
    secret: 'sua-chave-secreta-para-sessao',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Use 'true' se o seu site estiver com HTTPS
      maxAge: 1000 * 60 * 60 * 24 // 24 horas
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configuração da Estratégia do Google
passport.use(new GoogleStrategy({
    clientID: '874634983574-h6tooa1ekuh9ue16a5hjdri73csudgo4.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  async function(accessToken, refreshToken, profile, done) {
    console.log('--- Passport: Recebendo perfil do Google ---');
    console.log('Perfil recebido:', profile.id, profile.displayName);

    try {
        let currentUser = await User.findOne({ googleId: profile.id });

        if (currentUser) {
            console.log('--- Passport: Usuário já existe no DB. ---');
            if (currentUser.email === 'stringflowstore@gmail.com' && currentUser.role !== 'admin') {
                currentUser.role = 'admin';
                await currentUser.save();
                console.log('--- Passport: Papel do usuário atualizado para admin. ---');
            }
            return done(null, currentUser);
        } else {
            console.log('--- Passport: Usuário novo. Criando no DB. ---');
            const userEmail = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
            const newRole = userEmail === 'stringflowstore@gmail.com' ? 'admin' : 'user';

            const newUser = new User({
                googleId: profile.id,
                displayName: profile.displayName,
                email: userEmail,
                photo: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null,
                role: newRole
            });
            await newUser.save();
            console.log('--- Passport: Novo usuário salvo no DB. ---');
            return done(null, newUser);
        }
    } catch (err) {
        console.error('*** Passport: Erro no try/catch da estratégia Google:', err);
        return done(err, null);
    }
  }
));

// Serializa o usuário: salva o ID na sessão
passport.serializeUser((user, done) => {
    console.log('--- Passport: Serializando usuário. ID:', user.id);
    done(null, user.id); 
});

// Desserializa o usuário: encontra o usuário pelo ID na sessão
passport.deserializeUser(async (id, done) => {
    console.log('--- Passport: Desserializando usuário. ID:', id);
    try {
        const user = await User.findById(id);
        console.log('--- Passport: Usuário encontrado no DB. ---');
        done(null, user);
    } catch (err) {
        console.error('*** Passport: Erro ao desserializar o usuário:', err);
        done(err, null);
    }
});

// Rota para iniciar a autenticação com o Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// Rota de callback do Google, que redireciona após autenticação
app.get('/auth/google/callback',
  (req, res, next) => {
    console.log('--- Recebendo o callback do Google. Tentando autenticar... ---');
    next();
  },
  passport.authenticate('google', { failureRedirect: '/minha-conta.html' }),
  (req, res) => {
    console.log('--- Autenticação bem-sucedida! Redirecionando para /perfil.html ---');
    res.redirect('/perfil.html');
  }
);

// Rota para o logout
app.get('/logout', (req, res, next) => {
    console.log('--- Iniciando processo de logout... ---');
    req.logout((err) => {
        if (err) { return next(err); }
        console.log('--- Logout bem-sucedido! Redirecionando para /minha-conta.html ---');
        res.redirect('/minha-conta.html');
    });
});

// Middleware para proteger rotas (apenas usuários autenticados)
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    console.log('--- Tentativa de acesso a rota protegida sem autenticação. ---');
    res.redirect('/minha-conta.html');
}

// Rota para a página de perfil (protegida)
app.get('/perfil.html', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'WEBSITE', 'perfil.html'));
});

// Rota para verificar o estado do usuário e obter dados
app.get('/user-status', (req, res) => {
    if (req.isAuthenticated()) {
        console.log('--- Verificação de status: Usuário autenticado. ---');
        res.json({
            isLoggedIn: true,
            displayName: req.user.displayName,
            photo: req.user.photo,
            role: req.user.role
        });
    } else {
        console.log('--- Verificação de status: Usuário não autenticado. ---');
        res.json({ isLoggedIn: false });
    }
});

// Servidor de arquivos estáticos
app.use(express.static(path.join(__dirname, '..', 'WEBSITE')));
app.use('/images', express.static(path.join(__dirname, '..', 'WEBSITE', 'images')));

// Inicia o servidor
app.listen(port, (err) => {
    if (err) {
        return console.log('*** Algo deu errado ao iniciar o servidor:', err);
    }
    console.log(`Servidor rodando em http://localhost:${port}`);
});
