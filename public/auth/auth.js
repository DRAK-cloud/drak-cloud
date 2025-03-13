const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const axios = require('axios');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const MongoStore = require('connect-mongo');

const app = express();
const saltRounds = 12;

// Настройки безопасности
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Сессии с MongoDB хранилищем
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.DB_URL }),
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60 * 24 // 1 день
  }
}));

// Лимитер для авторизации
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 5,
  message: 'Слишком много попыток, попробуйте позже'
});

// Middleware проверки reCAPTCHA
async function verifyRecaptcha(token) {
  const response = await axios.post(
    `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET}&response=${token}`
  );
  return response.data.success;
}

// Маршрут регистрации
app.post('/register', authLimiter, async (req, res) => {
  try {
    // Валидация
    const { email, password, recaptcha } = req.body;
    if (!(email && password && recaptcha)) return res.status(400).send('Все поля обязательны');
    
    // Проверка reCAPTCHA
    const isHuman = await verifyRecaptcha(recaptcha);
    if (!isHuman) return res.status(403).send('Пройдите проверку reCAPTCHA');

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Сохранение пользователя в БД
    // Здесь добавьте логику сохранения в вашу БД
    // Пример: await User.create({ email, password: hashedPassword });

    res.status(201).send('Регистрация успешна');
  } catch (error) {
    res.status(500).send('Ошибка сервера');
  }
});

// Маршрут входа
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password, recaptcha } = req.body;
    
    // Проверка reCAPTCHA
    const isHuman = await verifyRecaptcha(recaptcha);
    if (!isHuman) return res.status(403).send('Пройдите проверку reCAPTCHA');

    // Поиск пользователя в БД
    // const user = await User.findOne({ email });
    // if (!user) return res.status(404).send('Пользователь не найден');

    // Проверка пароля
    // const validPassword = await bcrypt.compare(password, user.password);
    // if (!validPassword) return res.status(401).send('Неверный пароль');

    // Создание сессии
    req.session.user = { id: user._id, email: user.email };
    
    res.send('Вход выполнен');
  } catch (error) {
    res.status(500).send('Ошибка сервера');
  }
});

// Запуск сервера
app.listen(3000, () => {
  console.log('Сервер запущен на порту 3000');
});
