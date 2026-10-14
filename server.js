require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'secret', resave: false, saveUninitialized: false }));

mongoose.connect(process.env.MONGO_URI).then(async () => {
  console.log('MongoDB Connected');
  let admin = await User.findOne({ username: 'admin@gmail.com' });
  const hashedPassword = await bcrypt.hash('Admin@123', 10);
  if (!admin) {
    await User.create({ username: 'admin@gmail.com', password: hashedPassword, isAdmin: true });
    console.log('Default admin created: admin@gmail.com / Admin@123');
  } else {
    await User.updateOne({ username: 'admin@gmail.com' }, { password: hashedPassword, isAdmin: true });
    console.log('Admin credentials updated to: admin@gmail.com / Admin@123');
  }
});

const User = mongoose.model('User', new mongoose.Schema({ username: { type: String, unique: true }, password: String, isAdmin: { type: Boolean, default: false } }));
const Link = mongoose.model('Link', new mongoose.Schema({ userId: mongoose.Schema.Types.ObjectId, url: String, linkDetails: String }));

const auth = (req, res, next) => req.session.userId ? next() : res.redirect('/login');
const adminAuth = async (req, res, next) => {
  const user = req.session.userId ? await User.findById(req.session.userId) : null;
  user && user.isAdmin ? next() : res.status(403).send('Access denied. Admin only. <a href="/login">Login</a>');
};

const commonStyle = `
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f8f9fa; display: flex; justify-content: center; padding-top: 30px; margin: 0; }
    .container { width: 90%; max-width: 620px; background: #fff; border: 2px solid #2b6cb0; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); box-sizing: border-box; }
    .header-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    h2 { margin: 0; font-size: 22px; font-weight: bold; }
    .user-info { font-size: 12px; color: #555; }
    .input-box { width: 100%; padding: 8px 12px; font-size: 14px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; margin-bottom: 10px; outline: none; }
    .btn-group { display: flex; gap: 10px; margin-bottom: 15px; }
    .btn-save, .btn-primary { background: #007bff; color: white; border: none; padding: 8px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; border: 1px solid #e0e0e0; font-size: 13px; table-layout: fixed; }
    th, td { border: 1px solid #e0e0e0; padding: 8px; text-align: center; }
    .url-cell { text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .url-link { color: #3b82f6; text-decoration: none; }
    .copy-btn { color: #2e7d32; font-style: italic; cursor: pointer; background: none; border: none; }
    .delete-btn { color: #e53e3e; font-style: italic; text-decoration: none; }
    .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 15px; font-size: 13px; }
    .pagination a, .pagination span { padding: 4px 8px; border: 1px solid #ccc; border-radius: 4px; text-decoration: none; color: #007bff; }
    .pagination .active { background: #007bff; color: white; border-color: #007bff; }
    .pagination .disabled { color: #aaa; border-color: #eee; pointer-events: none; }
    .auth-link { margin-top: 10px; display: block; font-size: 14px; color: #007bff; text-decoration: none; }
  </style>
`;

// AUTH PAGES
app.get('/login', (req, res) => res.send(`
  <!DOCTYPE html><html><head><title>URL Manager - Login</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
  <body><div class="container">
    <div class="header-top"><h2>URL Manager</h2><span class="user-info">Login</span></div>
    <form action="/login" method="POST">
      <input type="text" name="username" placeholder="Username / Email" class="input-box" required>
      <input type="password" name="password" placeholder="Password" class="input-box" required>
      <div class="btn-group"><button type="submit" class="btn-primary">Login</button></div>
    </form>
    <a href="/register" class="auth-link">Don't have an account? Register</a>
  </div></body></html>
`));

app.get('/register', (req, res) => res.send(`
  <!DOCTYPE html><html><head><title>URL Manager - Register</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
  <body><div class="container">
    <div class="header-top"><h2>URL Manager</h2><span class="user-info">Register</span></div>
    <form action="/register" method="POST">
      <input type="text" name="username" placeholder="Username / Email" class="input-box" required>
      <input type="password" name="password" placeholder="Password" class="input-box" required>
      <div class="btn-group"><button type="submit" class="btn-primary">Register</button></div>
    </form>
    <a href="/login" class="auth-link">Already have an account? Login</a>
  </div></body></html>
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
    return res.redirect('/dashboard');
  }
  res.send('Invalid credentials. <a href="/login">Try again</a>');
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// DASHBOARD PAGE
app.get('/dashboard', auth, async (req, res) => {
  const page = parseInt(req.query.page) || 1, search = req.query.search || '';
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /mobile|android|iphone|ipad|tablet/i.test(userAgent);
  const limit = isMobile ? 20 : 10;

  const query = { userId: req.session.userId, $or: [{ url: { $regex: search,$options: 'i' } }, { linkDetails: { $regex: search,$options: 'i' } }] };
  const totalLinks = await Link.countDocuments(query);
  const totalPages = Math.ceil(totalLinks / limit) || 1;
  const links = await Link.find(query).skip((page - 1) * limit).limit(limit);

  let pageLinks = `<a href="${page > 1 ? `/dashboard?page=${page - 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === 1 ? 'disabled' : ''}">Previous</a>`;
  for (let i = 1; i <= totalPages; i++) pageLinks += `<a href="/dashboard?page=${i}&search=${encodeURIComponent(search)}" class="${i === page ? 'active' : ''}">${i}</a>`;
  pageLinks += `<a href="${page < totalPages ? `/dashboard?page=${page + 1}&search=${encodeURIComponent(search)}` : '#'}" class="${page === totalPages ? 'disabled' : ''}">Next ></a>`;

  res.send(`
    <!DOCTYPE html><html><head><title>URL Manager</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
    <body><div class="container">
      <div class="header-top">
        <h2>URL Manager</h2>
        <div class="user-info">${req.session.username} | <a href="/logout">Logout</a></div>
      </div>
      <form action="/add" method="POST">
        <input type="text" id="urlInput" name="url" placeholder="Enter URL" class="input-box" required>
        <input type="text" name="linkDetails" placeholder="Link Details / Description" class="input-box">
        <div class="btn-group">
          <button type="submit" class="btn-save">Save</button>
        </div>
      </form>
      <input type="text" id="liveSearch" value="${search}" placeholder="Search URL or details..." class="input-box" style="margin-bottom: 10px;" oninput="filterTable()">
      <table id="linksTable">
        <thead>
          <tr>
            <th style="width: 45%;">URL</th>
            <th style="width: 25%;">Link Details</th>
            <th style="width: 15%;">Copy</th>
            <th style="width: 15%;">Delete</th>
          </tr>
        </thead>
        <tbody>
          ${links.length ? links.map(item => {
            const formattedUrl = item.url.startsWith('http') ? item.url : 'https://' + item.url;
            return `
            <tr>
              <td class="url-cell">
                <a href="${formattedUrl}" target="_blank" rel="noopener noreferrer" class="url-link" title="${item.url}">${item.url}</a>
              </td>
              <td style="text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${item.linkDetails || '-'}</td>
              <td><button class="copy-btn" onclick="navigator.clipboard.writeText('${item.url}')">Copy</button></td>
              <td><a href="/delete/${item._id}" class="delete-btn">delete</a></td>
            </tr>
          `;
          }).join('') : '<tr><td colspan="4">No links found</td></tr>'}
        </tbody>
      </table>
      <div class="pagination">${pageLinks}</div>
    </div>
    <script>
      function filterTable() {
        const input = document.getElementById('liveSearch').value.toLowerCase();
        const rows = document.querySelectorAll('#linksTable tbody tr');
        rows.forEach(row => {
          row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none';
        });
      }
    </script>
    </body></html>
  `);
});

app.post('/add', auth, async (req, res) => {
  await Link.create({ url: req.body.url, linkDetails: req.body.linkDetails, userId: req.session.userId });
  res.redirect('/dashboard');
});

app.get('/delete/:id', auth, async (req, res) => {
  await Link.deleteOne({ _id: req.params.id, userId: req.session.userId });
  res.redirect('/dashboard');
});

// ADMIN PANEL PAGE
app.get('/administrator', adminAuth, async (req, res) => {
  const users = await User.find({});
  res.send(`
    <!DOCTYPE html><html><head><title>Admin Panel</title><meta name="viewport" content="width=device-width, initial-scale=1.0">${commonStyle}</head>
    <body><div class="container">
      <div class="header-top">
        <h2>Administrator Panel</h2>
        <div class="user-info"><a href="/dashboard">Dashboard</a> | <a href="/logout">Logout</a></div>
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
                ${!u.isAdmin ? `<a href="/admin/delete-user/${u._id}" class="delete-btn" onclick="return confirm('Delete user and all their links?')">Delete</a>` : '-'}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div></body></html>
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
  await User.deleteOne({ _id: req.params.id });
  res.redirect('/administrator');
});

app.get('/', (req, res) => res.redirect('/dashboard'));

app.listen(process.env.PORT || 3000, () => console.log('Server running on port 3000'));
