require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'secret', resave: false, saveUninitialized: false }));

// AES-256-CBC Encryption / Decryption Helpers
const ENCRYPTION_KEY = crypto.scryptSync(process.env.SESSION_SECRET || 'secretkey', 'salt', 32);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text || '';
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return text;
  }
}

mongoose.connect(process.env.MONGO_URI).then(async () => {
  console.log('MongoDB Connected');
  let admin = await User.findOne({ username: 'admin@gmail.com' });
  const hashedPassword = await bcrypt.hash('Admin@123', 10);
  if (!admin) {
    await User.create({ username: 'admin@gmail.com', password: hashedPassword, isAdmin: true });
    console.log('Default admin created: admin@gmail.com / Admin@123');
  } else {
    await User.updateOne({ username: 'admin@gmail.com' }, { password: hashedPassword, isAdmin: true });
    console.log('Admin credentials updated: admin@gmail.com / Admin@123');
  }
});

const User = mongoose.model('User', new mongoose.Schema({ username: { type: String, unique: true }, password: String, isAdmin: { type: Boolean, default: false } }));
const Link = mongoose.model('Link', new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, url: String, linkDetails: String }));
const Entry = mongoose.model('Entry', new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, website: String, url: String, username: String, password: String }));

const auth = (req, res, next) => req.session.userId ? next() : res.redirect('/login');
const adminAuth = async (req, res, next) => {
  const user = req.session.userId ? await User.findById(req.session.userId) : null;
  user && user.isAdmin ? next() : res.status(403).send('Access denied. Admin only. <a href="/login">Login</a>');
};

const commonStyle = `
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f8f9fa; margin: 0; padding: 0; display: flex; min-height: 100vh; }
    .layout { display: flex; width: 100%; }
    .sidebar { width: 220px; background: #ffffff; border-right: 1px solid #e0e0e0; padding: 20px 10px; box-sizing: border-box; flex-shrink: 0; }
    .sidebar h3 { font-size: 16px; margin-top: 0; margin-bottom: 20px; padding-left: 10px; color: #333; }
    .nav-item { display: flex; align-items: center; gap: 10px; padding: 10px; color: #333; text-decoration: none; border-radius: 6px; font-size: 14px; margin-bottom: 5px; }
    .nav-item:hover, .nav-item.active { background: #e8f0fe; color: #1a73e8; font-weight: bold; }
    .main-content { flex: 1; padding: 30px; display: flex; justify-content: center; }
    .container { width: 100%; max-width: 850px; background: #fff; border: 2px solid #2b6cb0; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); box-sizing: border-box; height: fit-content; }
    .header-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    h2 { margin: 0; font-size: 22px; font-weight: bold; color: #000; }
    .user-info { font-size: 12px; color: #555; }
    .input-box { width: 100%; padding: 8px 12px; font-size: 14px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; margin-bottom: 10px; outline: none; }
    .pwd-wrapper { display: flex; gap: 8px; margin-bottom: 10px; }
    .pwd-wrapper .input-box { margin-bottom: 0; }
    .btn-save, .btn-primary { background: #007bff; color: white; border: none; padding: 8px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
    .btn-show { background: #e2e8f0; border: 1px solid #cbd5e0; border-radius: 6px; padding: 0 12px; cursor: pointer; font-size: 13px; }
    .btn-group { display: flex; gap: 10px; margin-bottom: 15px; }
    table { width: 100%; border-collapse: collapse; border: 1px solid #e0e0e0; font-size: 13px; table-layout: fixed; }
    th, td { border: 1px solid #e0e0e0; padding: 8px; text-align: center; }
    th { font-weight: bold; background: #fff; }
    .url-cell { text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .user-cell { text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .url-link { color: #3b82f6; text-decoration: none; }
    .copy-btn { color: #2e7d32; font-style: italic; cursor: pointer; background: none; border: none; font-size: 13px; }
    .delete-btn { color: #e53e3e; font-style: italic; text-decoration: none; font-size: 13px; }
    .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 15px; font-size: 13px; }
    .pagination a, .pagination span { padding: 4px 8px; border: 1px solid #ccc; border-radius: 4px; text-decoration: none; color: #007bff; }
    .pagination .active { background: #007bff; color: white; border-color: #007bff; }
    .pagination .disabled { color: #aaa; border-color: #eee; pointer-events: none; }
    .auth-link { margin-top: 10px; display: block; font-size: 14px; color: #007bff; text-decoration: none; }
    @media (max-width: 768px) {
      .layout { flex-direction: column; }
      .sidebar { width: 100%; border-right: none; border-bottom: 1px solid #e0e0e0; padding: 10px; }
      .main-content { padding: 15px; }
    }
  </style>
`;

const renderLayout = (req, activeApp, content) => `
  <!DOCTYPE html><html><head><title>Dashboard</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
  <body>
    <div class="layout">
      <div class="sidebar">
        <h3>Applications</h3>
        <a href="/links" class="nav-item ${activeApp === 'links' ? 'active' : ''}">🔗 Link Manager</a>
        <a href="/passwords" class="nav-item ${activeApp === 'passwords' ? 'active' : ''}">🔑 Password Manager</a>
        <a href="/logout" class="nav-item" style="margin-top: 20px; color: #e53e3e;">🚪 Logout</a>
      </div>
      <div class="main-content">
        <div class="container">
          <div class="header-top">
            <h2>${activeApp === 'links' ? 'URL Manager' : 'Password Manager'}</h2>
            <div class="user-info">${req.session.username}</div>
          </div>
          ${content}
        </div>
      </div>
    </div>
  </body></html>
`;

// LOGIN PAGE
app.get('/login', (req, res) => res.send(`
  <!DOCTYPE html><html><head><title>Login</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
  <body style="justify-content: center; align-items: center;">
    <div class="container" style="margin-top: 50px;">
      <div class="header-top"><h2>Application Suite</h2><span class="user-info">Login</span></div>
      <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username / Email" class="input-box" required>
        <input type="password" name="password" placeholder="Password" class="input-box" required>
        <div class="btn-group"><button type="submit" class="btn-primary">Login</button></div>
      </form>
      <a href="/register" class="auth-link">Don't have an account? Register</a>
    </div>
  </body></html>
`));

// REGISTER PAGE
app.get('/register', (req, res) => res.send(`
  <!DOCTYPE html><html><head><title>Register</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
  <body style="justify-content: center; align-items: center;">
    <div class="container" style="margin-top: 50px;">
      <div class="header-top"><h2>Application Suite</h2><span class="user-info">Register</span></div>
      <form action="/register" method="POST">
        <input type="text" name="username" placeholder="Username / Email" class="input-box" required>
        <input type="password" name="password" placeholder="Password" class="input-box" required>
        <div class="btn-group"><button type="submit" class="btn-primary">Register</button></div>
      </form>
      <a href="/login" class="auth-link">Already have an account? Login</a>
    </div>
  </body></html>
`));

app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await User.create({ username: req.body.username, password: hashedPassword });
    res.redirect('/login');
  } catch { res.send('User exists. <a href="/register">Back</a>'); }
});

app.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.userId = user._id;
    req.session.username = user.username;
    return res.redirect('/links');
  }
  res.send('Invalid credentials. <a href="/login">Try again</a>');
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// 1. LINK MANAGER APP
app.get('/links', auth, async (req, res) => {
  const page = parseInt(req.query.page) || 1, search = req.query.search || '';
  const isMobile = /mobile|android|iphone|ipad|tablet/i.test(req.headers['user-agent'] || '');
  const limit = isMobile ? 20 : 10;

  const query = { userId: req.session.userId, $or: [{ url: { $regex: search,$options: 'i' } }, { linkDetails: { $regex: search,$options: 'i' } }] };
  const totalLinks = await Link.countDocuments(query);
  const totalPages = Math.ceil(totalLinks / limit) || 1;
  const links = await Link.find(query).sort({ _id: -1 }).skip((page - 1) * limit).limit(limit);

  let pageLinks = `<a href="${page > 1 ? `/links?page=${page - 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === 1 ? 'disabled' : ''}">Previous</a>`;
  for (let i = 1; i <= totalPages; i++) pageLinks += `<a href="/links?page=${i}&search=${encodeURIComponent(search)}" class="${i === page ? 'active' : ''}">${i}</a>`;
  pageLinks += `<a href="${page < totalPages ? `/links?page=${page + 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === totalPages ? 'disabled' : ''}">Next ></a>`;

  const content = `
    <form action="/links/add" method="POST">
      <input type="text" name="url" placeholder="Enter URL" class="input-box" required>
      <input type="text" name="linkDetails" placeholder="Link Details / Description" class="input-box">
      <div class="btn-group">
        <button type="submit" class="btn-save">Save Link</button>
      </div>
    </form>
    <input type="text" id="liveSearch" value="${search}" placeholder="Type to search all pages..." class="input-box" style="margin-bottom: 12px;" oninput="serverSearch('links')">
    <table id="linksTable">
      <thead>
        <tr>
          <th style="width: 40%;">URL</th>
          <th style="width: 32%;">Link Details</th>
          <th style="width: 14%;">Copy</th>
          <th style="width: 14%;">Delete</th>
        </tr>
      </thead>
      <tbody>
        ${links.length ? links.map(item => {
          const formattedUrl = item.url.startsWith('http') ? item.url : 'https://' + item.url;
          return `
          <tr>
            <td class="url-cell"><a href="${formattedUrl}" target="_blank" rel="noopener noreferrer" class="url-link" title="${item.url}">${item.url}</a></td>
            <td style="text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${item.linkDetails || '-'}</td>
            <td><button class="copy-btn" onclick="navigator.clipboard.writeText('${item.url.replace(/'/g, "\\'")}')">Copy</button></td>
            <td><a href="/links/delete/${item._id}" class="delete-btn" onclick="return confirm('Delete link?')">delete</a></td>
          </tr>
        `;
        }).join('') : '<tr><td colspan="4">No links found</td></tr>'}
      </tbody>
    </table>
    <div class="pagination">${pageLinks}</div>
    <script>
      let searchTimeout;
      function serverSearch(route) {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          const query = document.getElementById('liveSearch').value;
          window.location.href = '/' + route + '?search=' + encodeURIComponent(query);
        }, 400);
      }
    </script>
  `;
  res.send(renderLayout(req, 'links', content));
});

app.post('/links/add', auth, async (req, res) => {
  await Link.create({ url: req.body.url, linkDetails: req.body.linkDetails, userId: req.session.userId });
  res.redirect('/links');
});

app.get('/links/delete/:id', auth, async (req, res) => {
  await Link.deleteOne({ _id: req.params.id, userId: req.session.userId });
  res.redirect('/links');
});

// 2. PASSWORD MANAGER APP
app.get('/passwords', auth, async (req, res) => {
  const page = parseInt(req.query.page) || 1, search = req.query.search || '';
  const isMobile = /mobile|android|iphone|ipad|tablet/i.test(req.headers['user-agent'] || '');
  const limit = isMobile ? 20 : 10;

  const query = { 
    userId: req.session.userId, 
    $or: [
      { website: { $regex: search,$options: 'i' } },
      { url: { $regex: search,$options: 'i' } },
      { username: { $regex: search,$options: 'i' } }
    ] 
  };

  const totalEntries = await Entry.countDocuments(query);
  const totalPages = Math.ceil(totalEntries / limit) || 1;
  const entries = await Entry.find(query).sort({ _id: -1 }).skip((page - 1) * limit).limit(limit);

  let pageLinks = `<a href="${page > 1 ? `/passwords?page=${page - 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === 1 ? 'disabled' : ''}">Previous</a>`;
  for (let i = 1; i <= totalPages; i++) pageLinks += `<a href="/passwords?page=${i}&search=${encodeURIComponent(search)}" class="${i === page ? 'active' : ''}">${i}</a>`;
  pageLinks += `<a href="${page < totalPages ? `/passwords?page=${page + 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === totalPages ? 'disabled' : ''}">Next ></a>`;

  const content = `
    <form action="/passwords/add" method="POST">
      <input type="text" name="website" placeholder="Website Name" class="input-box" required>
      <input type="text" name="url" placeholder="Enter URL" class="input-box" required>
      <input type="text" name="username" placeholder="Username / Email" class="input-box">
      <div class="pwd-wrapper">
        <input type="password" id="addPwd" name="password" placeholder="Password" class="input-box">
        <button type="button" class="btn-show" onclick="const p=document.getElementById('addPwd'); p.type=p.type==='password'?'text':'password'; this.innerText=p.type==='password'?'Show':'Hide';">Show</button>
      </div>
      <div class="btn-group">
        <button type="submit" class="btn-save">Save Entry</button>
      </div>
    </form>
    <input type="text" id="liveSearch" value="${search}" placeholder="Type to search all pages..." class="input-box" style="margin-bottom: 12px;" oninput="serverSearch('passwords')">
    <table id="entriesTable">
      <thead>
        <tr>
          <th style="width: 18%;">Website</th>
          <th style="width: 32%;">Link</th>
          <th style="width: 36%;">Username</th>
          <th style="width: 14%;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${entries.length ? entries.map(item => {
          const formattedUrl = item.url.startsWith('http') ? item.url : 'https://' + item.url;
          const decryptedPwd = decrypt(item.password || '').replace(/'/g, "\\'");
          return `
          <tr>
            <td style="text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${item.website || '-'}</td>
            <td class="url-cell"><a href="${formattedUrl}" target="_blank" rel="noopener noreferrer" class="url-link" title="${item.url}">${item.url}</a></td>
            <td class="user-cell" title="${item.username \vert{}\vert{} ''}">${item.username || '-'}</td>
            <td>
              <button class="copy-btn" onclick="navigator.clipboard.writeText('${decryptedPwd}')">Copy</button>
              <a href="/passwords/delete/${item._id}" class="delete-btn" onclick="return confirm('Delete entry?')">delete</a>
            </td>
          </tr>
        `;
        }).join('') : '<tr><td colspan="4">No entries found</td></tr>'}
      </tbody>
    </table>
    <div class="pagination">${pageLinks}</div>
    <script>
      let searchTimeout;
      function serverSearch(route) {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          const query = document.getElementById('liveSearch').value;
          window.location.href = '/' + route + '?search=' + encodeURIComponent(query);
        }, 400);
      }
      
      const sInput = document.getElementById('liveSearch');
      if (sInput.value) {
        sInput.focus();
        sInput.setSelectionRange(sInput.value.length, sInput.value.length);
      }
    </script>
  `;
  res.send(renderLayout(req, 'passwords', content));
});

app.post('/passwords/add', auth, async (req, res) => {
  const encryptedPassword = encrypt(req.body.password);
  await Entry.create({ 
    website: req.body.website, 
    url: req.body.url, 
    username: req.body.username, 
    password: encryptedPassword, 
    userId: req.session.userId 
  });
  res.redirect('/passwords');
});

app.get('/passwords/delete/:id', auth, async (req, res) => {
  await Entry.deleteOne({ _id: req.params.id, userId: req.session.userId });
  res.redirect('/passwords');
});

// ADMIN PANEL
app.get('/administrator', adminAuth, async (req, res) => {
  const users = await User.find({});
  res.send(`
    <!DOCTYPE html><html><head><title>Admin Panel</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
    <body style="justify-content: center; padding-top: 30px;">
      <div class="container">
        <div class="header-top">
          <h2>Administrator Panel</h2>
          <div class="user-info"><a href="/links">Dashboard</a> | <a href="/logout">Logout</a></div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Update Username</th>
              <th>Reset Password</th>
              <th>Delete</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td>${u.isAdmin ? '<b>Admin</b>' : 'User'}</td>
                <td>
                  <form action="/admin/update-username" method="POST" style="display: flex; gap: 4px;">
                    <input type="hidden" name="userId" value="${u._id}">
                    <input type="text" name="newUsername" value="${u.username}" class="input-box" style="margin: 0; padding: 4px;" required>
                    <button type="submit" class="btn-primary" style="padding: 4px 8px; font-size: 11px;">Update</button>
                  </form>
                </td>
                <td>
                  <form action="/admin/reset-password" method="POST" style="display: flex; gap: 4px;">
                    <input type="hidden" name="userId" value="${u._id}">
                    <input type="password" name="newPassword" placeholder="New Pwd" class="input-box" style="margin: 0; padding: 4px;" required>
                    <button type="submit" class="btn-primary" style="padding: 4px 8px; font-size: 11px;">Reset</button>
                  </form>
                </td>
                <td>
                  ${!u.isAdmin ? `<a href="/admin/delete-user/${u._id}" class="delete-btn" onclick="return confirm('Delete user?')">delete</a>` : '-'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </body></html>
  `);
});

app.post('/admin/update-username', adminAuth, async (req, res) => {
  await User.updateOne({ _id: req.body.userId }, { username: req.body.newUsername });
  if (req.body.userId.toString() === req.session.userId.toString()) {
    req.session.username = req.body.newUsername;
  }
  res.redirect('/administrator');
});

app.post('/admin/reset-password', adminAuth, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
  await User.updateOne({ _id: req.body.userId }, { password: hashedPassword });
  res.redirect('/administrator');
});

app.get('/admin/delete-user/:id', adminAuth, async (req, res) => {
  await Link.deleteMany({ userId: req.params.id });
  await Entry.deleteMany({ userId: req.params.id });
  await User.deleteOne({ _id: req.params.id });
  res.redirect('/administrator');
});

app.get('/', (req, res) => res.redirect('/links'));

app.listen(process.env.PORT || 3000, () => console.log('Server running on port 3000'));
