const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// mysql://root:DzpeNxKzlBIRtAcRSbnWfKyMxmHSHbCK@shortline.proxy.rlwy.net:10235/railway
// Database connection pool
const pool = mysql.createPool({
  host: 'shortline.proxy.rlwy.net',
  user: 'root',
  port: '10235',
  password: 'DzpeNxKzlBIRtAcRSbnWfKyMxmHSHbCK',
  database: 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(conn => {
    console.log('✓ Database connected successfully');
    conn.release();
  })
  .catch(err => {
    console.error('✗ Database connection failed:', err.message);
  });

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed'));
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware - FIXED to check roleId
const requireAdmin = async (req, res, next) => {
  try {
    console.log('Admin middleware - Checking user:', req.user);
    
    // Get user's roleId from database
    const [users] = await pool.query(
      'SELECT u.roleId, r.roleName FROM users u LEFT JOIN role r ON u.roleId = r.roleId WHERE u.userId = ?',
      [req.user.id || req.user.userId]
    );

    if (users.length === 0) {
      console.log('Admin check - User not found');
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    console.log('Admin check - User roleId:', user.roleId, 'roleName:', user.roleName);

    // Check if roleId is 1 (admin) OR roleName is 'admin'
    if (user.roleId === 1 || user.roleName === 'admin') {
      console.log('Admin check - PASSED');
      next();
    } else {
      console.log('Admin check - FAILED');
      return res.status(403).json({ error: 'Admin access required' });
    }
  } catch (error) {
    console.error('Admin check error:', error);
    res.status(500).json({ error: 'Failed to verify admin status' });
  }
};

// ============= AUTH ROUTES =============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const [existing] = await pool.query(
      'SELECT userId FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Get user role ID (default to 2 for regular users, 1 is admin)
    const [roles] = await pool.query(
      'SELECT roleId FROM role WHERE roleName = ?',
      ['user']
    );

    const roleId = roles.length > 0 ? roles[0].roleId : 2;

    const [result] = await pool.query(
      'INSERT INTO users (name, email, pwd, roleId) VALUES (?, ?, ?, ?)',
      [name, email, password, roleId]
    );

    res.status(201).json({ 
      message: 'Registration successful',
      userId: result.insertId 
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login - FIXED to properly return role info
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const [users] = await pool.query(
      `SELECT u.userId, u.name, u.email, u.pwd, u.roleId, r.roleName 
       FROM users u 
       LEFT JOIN role r ON u.roleId = r.roleId 
       WHERE u.email = ?`,
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];

    const validPassword = (password === user.pwd);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('Login successful - User roleId:', user.roleId, 'roleName:', user.roleName);

    const tokenExpiry = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { 
        id: user.userId,
        userId: user.userId,
        email: user.email,
        roleId: user.roleId,
        roleName: user.roleName || (user.roleId === 1 ? 'admin' : 'user')
      },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    res.json({
      token,
      user: {
        id: user.userId,
        userId: user.userId,
        name: user.name,
        email: user.email,
        roleId: user.roleId,
        role: user.roleName || (user.roleId === 1 ? 'admin' : 'user'),
        roleName: user.roleName || (user.roleId === 1 ? 'admin' : 'user')
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      `SELECT u.userId, u.name, u.email, u.roleId, r.roleName, date_format(u.userFrom, '%m-%Y') as userFrom
       FROM users u
       LEFT JOIN role r ON u.roleId = r.roleId
       WHERE u.userId = ?`,
      [req.user.id || req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];
    res.json({
      id: user.userId,
      userId: user.userId,
      name: user.name,
      email: user.email,
      roleId: user.roleId,
      role: user.roleName || (user.roleId === 1 ? 'admin' : 'user'),
      roleName: user.roleName || (user.roleId === 1 ? 'admin' : 'user'),
      year: user.userFrom
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Get user's own posts
app.get('/api/auth/my-posts', authenticateToken, async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT c.*, u.name as author, cat.name as category,
             GROUP_CONCAT(DISTINCT t.tagName) as tags
      FROM content c
      LEFT JOIN users u ON c.authorId = u.userId
      LEFT JOIN category cat ON c.categoryId = cat.categoryId
      LEFT JOIN content_tags ct ON c.contentId = ct.contentId
      LEFT JOIN tags t ON ct.tagId = t.tagId
      WHERE c.authorId = ?
      GROUP BY c.contentId
      ORDER BY c.dateCreated DESC
    `, [req.user.id || req.user.userId]);

    const formatted = posts.map(post => ({
      id: post.contentId,
      title: post.title,
      excerpt: post.body ? post.body.substring(0, 200) + '...' : '',
      content: post.body,
      author: post.author,
      date: new Date(post.dateCreated).toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        year: 'numeric' 
      }),
      category: post.category,
      tags: post.tags ? post.tags.split(',') : [],
      views: post.views || 0,
      icon: '📝'
    }));

    res.json(formatted);
  } catch (error) {
    console.error('Get my posts error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// ============= CONTENT/POSTS ROUTES =============

// Get all content (public)
app.get('/api/posts', async (req, res) => {
  try {
    const { category, limit = 50, offset = 0 } = req.query;
    
    let query = `
      SELECT c.*, 
             u.name as author,
             cat.name as category,
             GROUP_CONCAT(DISTINCT t.tagName) as tags
      FROM content c
      LEFT JOIN users u ON c.authorId = u.userId
      LEFT JOIN category cat ON c.categoryId = cat.categoryId
      LEFT JOIN content_tags ct ON c.contentId = ct.contentId
      LEFT JOIN tags t ON ct.tagId = t.tagId
    `;
    
    const params = [];

    if (category) {
      query += ' WHERE cat.name = ?';
      params.push(category);
    }

    query += ' GROUP BY c.contentId ORDER BY c.dateCreated DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const [posts] = await pool.query(query, params);

    const formatted = posts.map(post => ({
      id: post.contentId,
      title: post.title,
      excerpt: post.body ? post.body.substring(0, 200) + '...' : '',
      author: post.author,
      date: new Date(post.dateCreated).toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        year: 'numeric' 
      }),
      category: post.category,
      tags: post.tags ? post.tags.split(',') : [],
      views: post.views || 0,
      icon: '📝'
    }));

    res.json(formatted);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Get single content by ID
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [posts] = await pool.query(
      `SELECT c.*, 
              u.name as author,
              u.email as authorEmail,
              u.userId as authorUserId,
              cat.name as category,
              GROUP_CONCAT(DISTINCT t.tagName) as tags
       FROM content c
       LEFT JOIN users u ON c.authorId = u.userId
       LEFT JOIN category cat ON c.categoryId = cat.categoryId
       LEFT JOIN content_tags ct ON c.contentId = ct.contentId
       LEFT JOIN tags t ON ct.tagId = t.tagId
       WHERE c.contentId = ?
       GROUP BY c.contentId`,
      [id]
    );

    if (posts.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const post = posts[0];
    res.json({
      id: post.contentId,
      title: post.title,
      content: post.body,
      author: post.author,
      authorEmail: post.authorEmail,
      authorId: post.authorUserId,
      category: post.category,
      categoryId: post.categoryId,
      date: new Date(post.dateCreated).toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        year: 'numeric' 
      }),
      dateCreated: post.dateCreated,
      tags: post.tags ? post.tags.split(',') : []
    });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

// Create content (authenticated users only)
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, category, tags, date } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    let categoryID = null;
    if (category) {
      const [categories] = await pool.query(
        'SELECT categoryId FROM category WHERE name = ?',
        [category]
      );
      
      if (categories.length > 0) {
        categoryID = categories[0].categoryId;
      } else {
        const [result] = await pool.query(
          'INSERT INTO Category (name) VALUES (?)',
          [category]
        );
        categoryID = result.insertId;
      }
    }

    const [result] = await pool.query(
      'INSERT INTO content (title, body, authorId, categoryId, dateCreated) VALUES (?, ?, ?, ?, ?)',
      [title, content, req.user.id || req.user.userId, categoryID, date || new Date()]
    );

    const contentID = result.insertId;

    if (tags && tags.length > 0) {
      for (const tagName of tags) {
        let [existingTags] = await pool.query(
          'SELECT tagId FROM tags WHERE tagName = ?',
          [tagName]
        );
        
        let tagId;
        if (existingTags.length > 0) {
          tagId = existingTags[0].tagId;
        } else {
          const [tagResult] = await pool.query(
            'INSERT INTO tags (tagName) VALUES (?)',
            [tagName]
          );
          tagId = tagResult.insertId;
        }
        
        await pool.query(
          'INSERT INTO content_tags (contentId, tagId) VALUES (?, ?)',
          [contentID, tagId]
        );
      }
    }

    res.status(201).json({ 
      message: 'Post created successfully',
      postId: contentID 
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Track article view
app.post('/api/posts/:id/view', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'UPDATE content SET views = views + 1 WHERE contentId = ?',
      [id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to track view' });
  }
});

// Update content
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [posts] = await pool.query(
      'SELECT authorId FROM Content WHERE contentId = ?',
      [id]
    );
    
    if (posts.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    // Check if user is author or admin (roleId = 1)
    const isAuthor = posts[0].authorId === (req.user.id || req.user.userId);
    const isAdmin = req.user.roleId === 1 || req.user.roleName === 'admin';

    if (!isAuthor && !isAdmin) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const { title, content, category, tags } = req.body;

    let categoryID = null;
    if (category) {
      const [categories] = await pool.query(
        'SELECT categoryId FROM category WHERE name = ?',
        [category]
      );
      
      if (categories.length > 0) {
        categoryID = categories[0].categoryId;
      } else {
        const [result] = await pool.query(
          'INSERT INTO category (name) VALUES (?)',
          [category]
        );
        categoryID = result.insertId;
      }
    }

    await pool.query(
      'UPDATE Content SET title = ?, body = ?, categoryId = ? WHERE contentId = ?',
      [title, content, categoryID, id]
    );

    if (tags) {
      await pool.query('DELETE FROM content_tags WHERE contentId = ?', [id]);
      
      for (const tagName of tags) {
        let [existingTags] = await pool.query(
          'SELECT tagId FROM tags WHERE tagName = ?',
          [tagName]
        );
        
        let tagId;
        if (existingTags.length > 0) {
          tagId = existingTags[0].tagId;
        } else {
          const [tagResult] = await pool.query(
            'INSERT INTO tags (tagName) VALUES (?)',
            [tagName]
          );
          tagId = tagResult.insertId;
        }
        
        await pool.query(
          'INSERT INTO content_tags (contentId, tagId) VALUES (?, ?)',
          [id, tagId]
        );
      }
    }

    res.json({ message: 'Post updated successfully' });
  } catch (error) {
    console.error('Update post error:', error);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Delete content
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [posts] = await pool.query(
      'SELECT authorId FROM Content WHERE contentId = ?',
      [id]
    );
    
    if (posts.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const isAuthor = posts[0].authorId === (req.user.id || req.user.userId);
    const isAdmin = req.user.roleId === 1 || req.user.roleName === 'admin';

    if (!isAuthor && !isAdmin) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    await pool.query('DELETE FROM content_tags WHERE contentId = ?', [id]);
    await pool.query('DELETE FROM comments WHERE contentId = ?', [id]);
    await pool.query('DELETE FROM content WHERE contentId = ?', [id]);
    
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// ============= COMMENTS ROUTES =============

app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [comments] = await pool.query(
      `SELECT c.*, u.name as userName, u.email
       FROM comments c
       LEFT JOIN users u ON c.userId = u.userId
       WHERE c.contentId = ?
       ORDER BY c.dateTime DESC`,
      [id]
    );

    res.json(comments);
  } catch (error) {
    console.error('Get comments error:', error);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Comment content required' });
    }

    const [result] = await pool.query(
      'INSERT INTO comments (userId, contentId, comment_body, dateTime) VALUES (?, ?, ?, NOW())',
      [req.user.id || req.user.userId, id, content]
    );

    res.status(201).json({ 
      message: 'Comment added successfully',
      commentId: result.insertId 
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// ============= CATEGORY ROUTES =============

app.get('/api/categories', async (req, res) => {
  try {
    const [categories] = await pool.query(
      `SELECT c.*, COUNT(co.contentId) as postCount
       FROM Category c
       LEFT JOIN Content co ON c.categoryId = co.categoryId
       GROUP BY c.categoryId`
    );

    res.json(categories);
  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// ============= ADMIN ROUTES =============

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [stats] = await pool.query(`
  SELECT 
    (SELECT COUNT(*) FROM content) as totalArticles,
    (SELECT COUNT(DISTINCT authorId) FROM content) as totalAuthors,
    (SELECT SUM(views) FROM content) as totalViews,
    (SELECT COUNT(*) FROM content WHERE DATE(dateCreated) = CURDATE()) as publishedToday
`);

    res.json({
      totalArticles: stats[0].totalArticles || 0,
      totalAuthors: stats[0].totalAuthors || 0,
      totalViews: stats[0].totalViews,
      publishedToday: stats[0].publishedToday || 0
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/posts', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT c.*, u.name as author, cat.name as category
      FROM content c
      LEFT JOIN users u ON c.authorId = u.userId
      LEFT JOIN category cat ON c.categoryId = cat.categoryId
      ORDER BY c.dateCreated DESC
    `);

    const formatted = posts.map(post => ({
      id: post.contentId,
      title: post.title,
      excerpt: post.body ? post.body.substring(0, 100) + '...' : '',
      author: post.author,
      date: new Date(post.dateCreated).toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        year: 'numeric' 
      }),
      icon: '📝',
      status: 'Published'
    }));

    res.json(formatted);
  } catch (error) {
    console.error('Get admin posts error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.post('/api/upload', authenticateToken, upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const imageUrl = `/uploads/${req.file.filename}`;
    res.json({ url: imageUrl });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

app.listen(PORT, () => {
  console.log(`✓ Server running on http://localhost:${PORT}`);
  console.log(`✓ Make sure to update database credentials in the code`);
});
