// Importa as bibliotecas necessárias
const express = require('express');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const port = process.env.PORT || 3000;

// Conexão com o MongoDB
const MONGODB_URI = 'mongodb+srv://stringflowstore:meAHcnUTJMU31A0F@stringflowstore.x4vhijf.mongodb.net/?retryWrites=true&w=majority&appName=StringFlowStore';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('--- Conectado ao MongoDB Atlas com sucesso! ---'))
  .catch(err => console.error('*** Erro de conexão com o MongoDB: ', err));

// ================= Schema de Usuário =================
const userSchema = new mongoose.Schema({
    googleId: String,
    displayName: String,
    email: { type: String, unique: true, sparse: true }, 
    password: String,
    photo: String,
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// ================= Schema de Produto =================
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    stock: { type: Number, required: true },
    sold: { type: Number, default: 0 },
    category: { type: String, enum: ['Instrumentos', 'Acessórios'], required: true },
    subcategory: { type: String, required: true },
    description: { type: String, default: '' },
    photo: { type: String, default: '' }
}, { timestamps: true });
const Product = mongoose.model('Product', productSchema);

// ================= Middlewares =================
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'sua-chave-secreta-para-sessao',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(passport.initialize());
app.use(passport.session());

// ================= Google Strategy =================
passport.use(new GoogleStrategy({
    clientID: '874634983574-h6tooa1ekuh9ue16a5hjdri73csudgo4.apps.googleusercontent.com', 
    clientSecret: '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',
    callbackURL: "https://backend-fk1s.onrender.com/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (user) {
            if (user.email === 'stringflowstore@gmail.com' && user.role !== 'admin') {
                user.role = 'admin';
                await user.save();
            }
            return done(null, user);
        } else {
            const userEmail = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
            const userPhoto = profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null;
            const newRole = userEmail === 'stringflowstore@gmail.com' ? 'admin' : 'user';

            const newUser = new User({
                googleId: profile.id,
                displayName: profile.displayName,
                email: userEmail,
                photo: userPhoto,
            });
            newUser.role = newRole;
            await newUser.save();
            return done(null, newUser);
        }
    } catch (err) {
        console.error('Erro GoogleStrategy:', err);
        return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// ================= Rotas Google =================
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/minha-conta.html' }),
    (req, res) => res.redirect('/minha-conta.html')
);

// ================= Rotas Login/Cadastro Local =================
app.post('/register', async (req, res) => {
    try {
        const { displayName, email, password } = req.body;
        if (!displayName || !email || !password) return res.status(400).send('Preencha todos os campos');

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('Usuário já existe');

        const hashedPassword = await bcrypt.hash(password, 10);
        const role = email === 'stringflowstore@gmail.com' ? 'admin' : 'user';

        const newUser = new User({ displayName, email, password: hashedPassword, role });
        await newUser.save();

        req.login(newUser, (err) => {
            if (err) return res.status(500).send('Erro ao logar');
            res.redirect('/minha-conta.html');
        });
    } catch (err) {
        console.error('Erro no /register:', err);
        res.status(500).send('Erro interno');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Usuário não encontrado');
        if (!user.password) return res.status(400).send('Usuário cadastrado apenas via Google');

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).send('Senha incorreta');

        req.login(user, (err) => {
            if (err) return res.status(500).send('Erro ao logar');
            res.redirect('/minha-conta.html');
        });
    } catch (err) {
        console.error('Erro no /login:', err);
        res.status(500).send('Erro interno');
    }
});

// ================= Logout =================
app.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) return next(err);
        res.redirect('/minha-conta.html');
    });
});

// ================= Middleware =================
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/minha-conta.html');
}
function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    res.redirect('/minha-conta.html');
}

// ================= Rotas Protegidas =================
// ⚠️ CORRIGIDO: Adiciona a rota explícita para a página de minha-conta.
app.get('/minha-conta.html', ensureAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, '..', 'WEBSITE', 'minha-conta.html'))
);

app.get('/painel.html', ensureAdmin, (req, res) =>
    res.sendFile(path.join(__dirname, '..', 'WEBSITE', 'painel.html'))
);

// ================= Status do Usuário =================
app.get('/user-status', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            isLoggedIn: true,
            displayName: req.user.displayName,
            photo: req.user.photo || 'images/minha-conta.png',
            role: req.user.role
        });
    } else {
        res.json({ isLoggedIn: false });
    }
});

// ================= Servidor Estático =================
app.use(express.static(path.join(__dirname, '..', 'WEBSITE')));
app.use('/images', express.static(path.join(__dirname, '..', 'WEBSITE', 'images')));

// ================= Rotas Admin =================
app.get('/admin/users', ensureAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ createdAt: -1 });
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao buscar usuários');
    }
});

app.get('/admin/products', ensureAdmin, async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao buscar produtos');
    }
});

// ================= Rota de criação de produto (melhorada) =================
app.post('/admin/products', ensureAdmin, async (req, res) => {
    try {
        const { name, price, stock, category, subcategory, description, photo } = req.body;

        if (!name || !price || !stock || !category || !subcategory) {
            return res.status(400).send('Campos obrigatórios faltando');
        }

        const newProduct = new Product({ name, price, stock, category, subcategory, description, photo });
        await newProduct.save();

        res.status(201).json(newProduct);
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao adicionar produto');
    }
});

app.put('/admin/products/:id', ensureAdmin, async (req, res) => {
    try {
        const { name, price, stock, category, subcategory, description, photo } = req.body;
        await Product.findByIdAndUpdate(req.params.id, { name, price, stock, category, subcategory, description, photo });
        res.send('Produto atualizado com sucesso');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao atualizar produto');
    }
});

app.delete('/admin/products/:id', ensureAdmin, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.send('Produto removido com sucesso');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao remover produto');
    }
});

// Rota pública para pegar produtos por categoria
app.get('/products/:category', async (req, res) => {
    try {
        const category = req.params.category;
        const products = await Product.find({ category }).sort({ createdAt: -1 });
        res.json(products);
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao buscar produtos');
    }
});

// ================= Inicia Servidor =================
app.listen(port, err => {
    if (err) return console.error('Erro ao iniciar servidor:', err);
    console.log(`Servidor rodando em http://localhost:${port}`);
});