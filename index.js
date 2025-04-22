const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const basicAuth = require('basic-auth');

app.use(bodyParser.json());

const users = {};

app.post('/signup', (req, res) => {
  const { user_id, password } = req.body;

  if (!user_id || !password) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Required user_id and password"
    });
  }
  if (user_id.length < 6 || user_id.length > 20 || !/^[a-zA-Z0-9]+$/.test(user_id)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Input length is incorrect"
    });
  }
  if (password.length < 8 || password.length > 20 || /[^ -~]/.test(password)) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Incorrect character pattern"
    });
  }
  if (users[user_id]) {
    return res.status(400).json({
      message: "Account creation failed",
      cause: "Already same user_id is used"
    });
  }

  const hashed = bcrypt.hashSync(password, 10);
  users[user_id] = { password: hashed, nickname: user_id, comment: "" };

  res.json({
    message: "Account successfully created",
    user: {
      user_id,
      nickname: user_id
    }
  });
});

app.get('/users/:user_id', (req, res) => {
  const auth = basicAuth(req);
  const { user_id } = req.params;

  if (!users[user_id]) {
    return res.status(404).json({ message: "No user found" });
  }

  if (!auth || auth.name !== user_id || !bcrypt.compareSync(auth.pass, users[user_id].password)) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  const { nickname, comment } = users[user_id];
  res.json({
    message: "User details by user_id",
    user: { user_id, nickname, comment }
  });
});

app.patch('/users/:user_id', (req, res) => {
  const auth = basicAuth(req);
  const { user_id } = req.params;
  const { nickname, comment } = req.body;

  if (!users[user_id]) return res.status(404).json({ message: "No user found" });

  if (!auth || auth.name !== user_id || !bcrypt.compareSync(auth.pass, users[user_id].password)) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  if ('user_id' in req.body || 'password' in req.body) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Not updatable user_id and password"
    });
  }

  if (!nickname && !comment) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Required nickname or comment"
    });
  }

  if ((nickname && nickname.length > 30) || (comment && comment.length > 100)) {
    return res.status(400).json({
      message: "User updation failed",
      cause: "Invalid nickname or comment"
    });
  }

  if (nickname !== undefined) users[user_id].nickname = nickname;
  if (comment !== undefined) users[user_id].comment = comment;

  res.json({
    message: "User successfully updated",
    user: {
      nickname: users[user_id].nickname,
      comment: users[user_id].comment
    }
  });
});

app.post('/close', (req, res) => {
  const auth = basicAuth(req);

  if (!auth || !users[auth.name] || !bcrypt.compareSync(auth.pass, users[auth.name].password)) {
    return res.status(401).json({ message: "Authentication failed" });
  }

  delete users[auth.name];
  res.json({ message: "Account and user successfully deleted" });
});

app.get('/', (req, res) => {
  res.send("Auth API is running!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
