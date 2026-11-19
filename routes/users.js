const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { requireLogin, requireAdmin } = require('../middleware/auth');

const router = express.Router();
const UPLOADS = path.join(__dirname, '..', 'uploads');

const storage = multer.diskStorage({
  destination: UPLOADS,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpe?g|gif|webp)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('La foto debe ser una imagen (png, jpg, gif o webp).'));
  }
});

function removePhoto(filename) {
  if (!filename) return;
  fs.unlink(path.join(UPLOADS, filename), () => {});
}

const SELECT_USERS = `
  SELECT u.id, u.username, u.name, u.email, u.role, u.group_id, u.photo, g.name AS groupName
  FROM users u LEFT JOIN groups g ON g.id = u.group_id`;

// Listado: el admin ve todos; un usuario ve a los miembros de su grupo
router.get('/', requireLogin, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = db.all(`${SELECT_USERS} ORDER BY u.id`);
  } else if (req.user.group_id) {
    rows = db.all(`${SELECT_USERS} WHERE u.group_id = ? ORDER BY u.name`, req.user.group_id);
  } else {
    rows = db.all(`${SELECT_USERS} WHERE u.id = ?`, req.user.id);
  }
  rows = rows.map((u) => ({ ...u, groupName: u.groupName || '—' }));
  res.render('users/list', { title: 'Usuarios', users: rows });
});

router.get('/new', requireLogin, requireAdmin, (req, res) => {
  const groups = db.all('SELECT * FROM groups ORDER BY name');
  res.render('users/new', { title: 'Alta de usuario', groups, error: null, form: {} });
});

router.post('/', requireLogin, requireAdmin, (req, res) => {
  upload.single('photo')(req, res, (uploadErr) => {
    const form = {
      username: (req.body.username || '').trim(),
      name: (req.body.name || '').trim(),
      email: (req.body.email || '').trim(),
      groupId: req.body.groupId || ''
    };
    const password = req.body.password || '';
    const photo = req.file ? req.file.filename : null;

    const fail = (error) => {
      removePhoto(photo);
      res.status(400).render('users/new', {
        title: 'Alta de usuario',
        groups: db.all('SELECT * FROM groups ORDER BY name'),
        error,
        form
      });
    };

    if (uploadErr) return fail(uploadErr.message);
    if (!form.username || !form.name || !form.email || !password) {
      return fail('Usuario, nombre, email y contraseña son obligatorios.');
    }
    if (!/^[a-zA-Z0-9_.-]{3,20}$/.test(form.username)) {
      return fail('El usuario debe tener entre 3 y 20 caracteres (letras, números, puntos, guiones o guion bajo).');
    }
    if (password.length < 6) return fail('La contraseña debe tener al menos 6 caracteres.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) return fail('El email no es válido.');
    if (db.get('SELECT 1 AS ok FROM users WHERE username = ?', form.username)) {
      return fail('Ese nombre de usuario ya existe.');
    }

    let groupId = null;
    if (form.groupId) {
      groupId = parseInt(form.groupId, 10);
      if (!db.get('SELECT 1 AS ok FROM groups WHERE id = ?', groupId)) {
        return fail('El grupo seleccionado no existe.');
      }
    }

    db.run(
      `INSERT INTO users (username, name, email, password_hash, role, group_id, photo)
       VALUES (?, ?, ?, ?, 'user', ?, ?)`, // un usuario solo puede pertenecer a un único grupo
      form.username,
      form.name,
      form.email,
      bcrypt.hashSync(password, 10),
      groupId,
      photo
    );
    req.session.flash = { type: 'ok', text: 'Usuario creado correctamente.' };
    res.redirect('/users');
  });
});

router.post('/:id/delete', requireLogin, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = db.get('SELECT * FROM users WHERE id = ?', id);

  if (!user) {
    req.session.flash = { type: 'error', text: 'El usuario no existe.' };
  } else if (user.role === 'admin') {
    req.session.flash = { type: 'error', text: 'No se puede dar de baja al administrador.' };
  } else {
    removePhoto(user.photo);
    // Sus mensajes se conservan en el chat como "Usuario eliminado" (ON DELETE SET NULL)
    db.run('DELETE FROM users WHERE id = ?', id);
    req.session.flash = { type: 'ok', text: 'Usuario dado de baja.' };
  }
  res.redirect('/users');
});

module.exports = router;
