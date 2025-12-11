require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const cron = require('node-cron');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const emailWorker = require('./services/emailWorker');

// Configure multer for logo uploads
const logoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `school-logo-${Date.now()}${ext}`);
  }
});

const logoUpload = multer({
  storage: logoStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|svg|webp/;
    const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mime = allowedTypes.test(file.mimetype);
    if (ext && mime) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, svg, webp)'));
    }
  }
});

const app = express();
const PORT = process.env.PORT || 3002;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected successfully');
  }
});

// Email transporter setup (DEPRECATED - now using DB settings)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Helper function to get email transporter from database settings
async function getEmailTransporter(schoolId = 2) {
  try {
    const result = await pool.query(
      'SELECT smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, smtp_from_name, smtp_use_tls FROM booking_settings WHERE school_id = $1',
      [schoolId]
    );

    if (result.rows.length === 0 || !result.rows[0].smtp_host) {
      // Fallback to hardcoded transporter if no settings found
      console.warn('No email settings found in DB, using fallback transporter');
      return transporter;
    }

    const settings = result.rows[0];

    return nodemailer.createTransport({
      host: settings.smtp_host,
      port: settings.smtp_port,
      secure: settings.smtp_port === 465,
      auth: {
        user: settings.smtp_username,
        pass: settings.smtp_password
      },
      tls: {
        rejectUnauthorized: settings.smtp_use_tls
      }
    });
  } catch (error) {
    console.error('Error getting email transporter:', error);
    // Fallback to hardcoded transporter
    return transporter;
  }
}

// Generate iCal calendar invite
function generateCalendarInvite(booking, guide) {
  const now = new Date();
  const tourDate = booking.booking_type === 'open_day' && booking.event_date
    ? new Date(booking.event_date)
    : new Date(booking.scheduled_date);

  const tourTime = booking.booking_type === 'open_day' && booking.start_time
    ? booking.start_time
    : booking.scheduled_time;

  // Parse time and set on date
  const [hours, minutes] = tourTime.split(':');
  tourDate.setHours(parseInt(hours), parseInt(minutes), 0, 0);

  // End time (assume 1 hour tour)
  const endDate = new Date(tourDate);
  endDate.setHours(endDate.getHours() + 1);

  // Format dates for iCal (YYYYMMDDTHHMMSSZ)
  const formatDate = (date) => {
    return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  };

  const tourType = booking.booking_type === 'open_day' ? 'Open Day Tour'
    : booking.booking_type === 'taster_day' ? 'Taster Day'
    : 'Private Tour';
  const parentName = `${booking.parent_first_name} ${booking.parent_last_name}`;
  const studentInfo = booking.student_first_name
    ? `\nStudent: ${booking.student_first_name} ${booking.student_last_name || ''}`
    : '';

  const description = `Tour Details:\\n` +
    `Type: ${tourType}\\n` +
    `Parent: ${parentName}\\n` +
    `Email: ${booking.email}\\n` +
    `Phone: ${booking.phone || 'Not provided'}${studentInfo}\\n` +
    `Attendees: ${booking.num_attendees}\\n` +
    `Special Requirements: ${booking.special_requirements || 'None'}`;

  const icsContent = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//More House School//Tour Booking//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:REQUEST',
    'BEGIN:VEVENT',
    `UID:booking-${booking.id}@morehouseschool.com`,
    `DTSTAMP:${formatDate(now)}`,
    `DTSTART:${formatDate(tourDate)}`,
    `DTEND:${formatDate(endDate)}`,
    `SUMMARY:${tourType}: ${parentName}`,
    `DESCRIPTION:${description}`,
    `LOCATION:More House School`,
    `ORGANIZER;CN=More House School:MAILTO:booking@morehousemail.org.uk`,
    `ATTENDEE;CN=${guide.name};RSVP=TRUE:MAILTO:${guide.email}`,
    'STATUS:CONFIRMED',
    'SEQUENCE:0',
    'BEGIN:VALARM',
    'TRIGGER:-PT24H',
    'ACTION:DISPLAY',
    'DESCRIPTION:Tour Reminder - Tomorrow',
    'END:VALARM',
    'BEGIN:VALARM',
    'TRIGGER:-PT1H',
    'ACTION:DISPLAY',
    'DESCRIPTION:Tour starts in 1 hour',
    'END:VALARM',
    'END:VEVENT',
    'END:VCALENDAR'
  ].join('\r\n');

  return icsContent;
}

// Send tour guide notification with calendar invite
async function sendTourGuideNotification(booking, guide, notificationType = 'assignment') {
  try {
    const tourDate = booking.booking_type === 'open_day' && booking.event_date
      ? new Date(booking.event_date)
      : new Date(booking.scheduled_date);

    const tourTime = booking.booking_type === 'open_day' && booking.start_time
      ? booking.start_time
      : booking.scheduled_time;

    const formattedDate = tourDate.toLocaleDateString('en-GB', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    const tourType = booking.booking_type === 'open_day' ? 'Open Day Tour'
      : booking.booking_type === 'taster_day' ? 'Taster Day'
      : 'Private Tour';
    const parentName = `${booking.parent_first_name} ${booking.parent_last_name}`;
    const studentName = booking.student_first_name
      ? `${booking.student_first_name} ${booking.student_last_name || ''}`
      : 'N/A';

    // Determine which template to use
    let templateId;
    if (notificationType === 'assignment') {
      templateId = 28; // Tour Guide - Assignment
    } else if (notificationType === 'reminder_first') {
      templateId = 29; // Tour Guide - First Reminder
    } else if (notificationType === 'reminder_final') {
      templateId = 30; // Tour Guide - Final Reminder
    }

    // Prepare template data
    const feedbackFormPage = booking.booking_type === 'taster_day'
      ? 'taster-feedback-form.html'
      : 'tour-feedback-form.html';

    const templateData = {
      guide_name: guide.name,
      tour_type: tourType,
      tour_date: formattedDate,
      tour_time: tourTime,
      parent_name: parentName,
      parent_email: booking.email,
      parent_phone: booking.phone || 'Not provided',
      student_name: studentName,
      num_attendees: booking.num_attendees,
      special_requirements: booking.special_requirements || 'None',
      feedback_link: booking.feedback_token
        ? `${process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com'}/${feedbackFormPage}?token=${booking.feedback_token}`
        : ''
    };

    // Prepare attachments (calendar invite for assignment only)
    const attachments = notificationType === 'assignment' ? [{
      filename: 'tour-invite.ics',
      content: generateCalendarInvite(booking, guide),
      contentType: 'text/calendar'
    }] : [];

    // Send using template
    await sendInternalTemplateEmail(templateId, guide.email, templateData, attachments);

    console.log(`✓ Sent ${notificationType} notification to tour guide: ${guide.email}`);
    return true;
  } catch (error) {
    console.error(`Error sending tour guide notification:`, error);
    return false;
  }
}

// Send feedback notification to admissions team
async function sendFeedbackNotification(booking, responses, submissionNumber) {
  try {
    const tourDate = booking.booking_type === 'open_day' && booking.event_date
      ? new Date(booking.event_date)
      : new Date(booking.scheduled_date);

    const formattedDate = tourDate.toLocaleDateString('en-GB', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    const tourType = booking.booking_type === 'open_day' ? 'Open Day Tour'
      : booking.booking_type === 'taster_day' ? 'Taster Day'
      : 'Private Tour';
    const parentName = `${booking.parent_first_name} ${booking.parent_last_name}`;
    const studentName = `${booking.student_first_name} ${booking.student_last_name}`;

    // Format responses as plain text for email template
    const feedbackResponses = Object.entries(responses).map(([key, value]) => {
      const label = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
      let displayValue = value;

      if (Array.isArray(value)) {
        displayValue = value.join(', ');
      }

      if (key.includes('rating') && !isNaN(value)) {
        displayValue = `${value}/5`;
      }

      return `${label}: ${displayValue || '-'}`;
    }).join('\n');

    // Prepare template data
    const templateData = {
      submission_number: submissionNumber,
      guide_name: booking.guide_name,
      tour_type: tourType,
      tour_date: formattedDate,
      parent_name: parentName,
      student_name: studentName,
      feedback_responses: feedbackResponses
    };

    // Get admin email from environment
    const adminEmail = process.env.ADMIN_EMAIL;

    // Send using template (ID 31 = Admissions - Feedback Notification)
    await sendInternalTemplateEmail(31, adminEmail, templateData);

    console.log(`✓ Feedback notification sent to ${adminEmail}`);
    return true;
  } catch (error) {
    console.error(`Error sending feedback notification:`, error);
    return false;
  }
}

// Send booking notification to admissions team
async function sendAdmissionsBookingNotification(booking) {
  try {
    const parentName = `${booking.parent_first_name} ${booking.parent_last_name}`;
    const studentName = `${booking.student_first_name} ${booking.student_last_name || ''}`.trim();

    // Get event details if it's an open day or taster day with event
    let event = null;
    if (booking.event_id) {
      const eventResult = await pool.query('SELECT * FROM events WHERE id = $1', [booking.event_id]);
      event = eventResult.rows[0];
    }

    // Format dates
    const bookedAt = new Date(booking.booked_at).toLocaleString('en-GB', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    let eventDate = '';
    let eventTime = '';
    if (event) {
      eventDate = new Date(event.event_date).toLocaleDateString('en-GB', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
      eventTime = `${event.start_time} - ${event.end_time}`;
    }

    // Prepare template data
    const templateData = {
      parent_name: parentName,
      student_name: studentName,
      email: booking.email,
      phone: booking.phone,
      event_title: event ? event.title : '',
      event_date: eventDate,
      event_time: eventTime,
      scheduled_date: booking.scheduled_date || 'To be confirmed',
      scheduled_time: booking.scheduled_time || 'To be confirmed',
      num_attendees: booking.num_attendees,
      special_requirements: booking.special_requirements || '',
      preferred_language: booking.preferred_language || '',
      status: booking.status.charAt(0).toUpperCase() + booking.status.slice(1),
      booked_at: bookedAt
    };

    // Get admin email from environment
    const adminEmail = process.env.ADMIN_EMAIL;

    // Get the appropriate template ID based on booking type
    const templateId = await getTemplateId(booking.booking_type, 'admissions_notification', booking.school_id);

    if (templateId) {
      // Send notification using template, CC parent for transparency
      await sendInternalTemplateEmail(templateId, adminEmail, templateData, [], booking.email);
      console.log(`✓ Admissions booking notification sent to ${adminEmail} (CC: ${booking.email}) for ${booking.booking_type} booking`);
      return true;
    } else {
      console.error(`❌ No admissions notification template found for booking_type: ${booking.booking_type}`);
      return false;
    }
  } catch (error) {
    console.error('Error sending admissions booking notification:', error);
    return false;
  }
}

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Disable caching for all static files
app.use(express.static('public', {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// Session configuration
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: false // Set to true if using HTTPS
  }
}));

// ============================================================================
// ADMIN USERS CONFIGURATION
// ============================================================================

// Admin users from environment variables (same as CRM)
const ADMIN_USERS = [
  {
    email: process.env.ADMIN_USER1_EMAIL,
    password: process.env.ADMIN_USER1_PASSWORD
  },
  {
    email: process.env.ADMIN_USER2_EMAIL,
    password: process.env.ADMIN_USER2_PASSWORD
  },
  {
    email: process.env.ADMIN_USER3_EMAIL,
    password: process.env.ADMIN_USER3_PASSWORD
  }
].filter(user => user.email && user.password);

console.log(`[BOOKING APP] Loaded ${ADMIN_USERS.length} admin user(s) from environment`);

// Sync admin users from environment to database on startup
async function syncAdminUsersToDatabase() {
  if (ADMIN_USERS.length === 0) {
    console.log('[BOOKING APP] No admin users to sync from environment');
    return;
  }

  console.log(`[BOOKING APP] Syncing ${ADMIN_USERS.length} admin user(s) to database...`);

  for (const user of ADMIN_USERS) {
    try {
      // Check if user already exists
      const existingUser = await pool.query(
        'SELECT id, email FROM admin_users WHERE email = $1',
        [user.email.toLowerCase()]
      );

      if (existingUser.rows.length > 0) {
        // User exists - update password hash
        const passwordHash = await bcrypt.hash(user.password, 10);
        await pool.query(
          `UPDATE admin_users
           SET password_hash = $1, is_active = true, updated_at = NOW()
           WHERE email = $2`,
          [passwordHash, user.email.toLowerCase()]
        );
        console.log(`[BOOKING APP] Updated existing user: ${user.email}`);
      } else {
        // Create new user with booking permissions
        const passwordHash = await bcrypt.hash(user.password, 10);
        await pool.query(
          `INSERT INTO admin_users (email, password_hash, role, is_active, permissions, school_id, created_at, updated_at)
           VALUES ($1, $2, 'admin', true, $3, 2, NOW(), NOW())`,
          [
            user.email.toLowerCase(),
            passwordHash,
            JSON.stringify({ can_access_booking: true, can_access_crm: true })
          ]
        );
        console.log(`[BOOKING APP] Created new user: ${user.email}`);
      }
    } catch (error) {
      console.error(`[BOOKING APP] Error syncing user ${user.email}:`, error.message);
    }
  }

  console.log('[BOOKING APP] Admin user sync complete');
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

// Simple admin auth check
const requireAdminAuth = (req, res, next) => {
  if (req.session && req.session.adminEmail) {
    return next();
  }
  return res.status(401).json({
    success: false,
    error: 'Authentication required'
  });
};

// Admin auth check that also accepts API key (for cross-app communication)
const requireAdminOrApiKey = (req, res, next) => {
  // Check session auth first
  if (req.session && req.session.adminEmail) {
    return next();
  }

  // Check API key from header
  const apiKey = req.headers['x-api-key'];
  if (apiKey && process.env.ADMIN_API_KEY && apiKey === process.env.ADMIN_API_KEY) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: 'Authentication required'
  });
};

// Legacy authentication middleware (for old parent bookings system)
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ success: false, error: 'Authentication required' });
  }
};

const requireAdmin = async (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ success: false, error: 'Authentication required' });
  }

  try {
    const result = await pool.query(
      'SELECT role FROM admin_users WHERE id = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0 || (result.rows[0].role !== 'admin' && result.rows[0].role !== 'super_admin')) {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }

    next();
  } catch (error) {
    console.error('Admin check error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
};

// ============================================================================
// ADMIN AUTHENTICATION ROUTES
// ============================================================================

/**
 * POST /api/admin/login
 * Admin login endpoint
 */
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;

  console.log('[BOOKING APP] Login attempt for:', email);

  try {
    // Query database for user
    const result = await pool.query(
      'SELECT id, email, password_hash, permissions, is_active FROM admin_users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      console.log(`[BOOKING APP] Failed login attempt - user not found: ${email}`);
      return res.json({ success: false, error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Check if user is active
    if (!user.is_active) {
      console.log(`[BOOKING APP] Failed login attempt - user inactive: ${email}`);
      return res.json({ success: false, error: 'Account is inactive' });
    }

    // Check password
    const bcrypt = require('bcrypt');
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      console.log(`[BOOKING APP] Failed login attempt - invalid password: ${email}`);
      return res.json({ success: false, error: 'Invalid email or password' });
    }

    // Check permissions - user must have can_access_booking permission
    const permissions = user.permissions || {};
    if (!permissions.can_access_booking) {
      console.log(`[BOOKING APP] Failed login attempt - no booking access permission: ${email}`);
      return res.json({ success: false, error: 'You do not have permission to access the booking app' });
    }

    // Login successful
    req.session.adminEmail = email;
    req.session.adminUser = { email, permissions };

    // Force session save before responding
    req.session.save((err) => {
      if (err) {
        console.error('[BOOKING APP] Session save error:', err);
        return res.json({ success: false, error: 'Session error' });
      }
      console.log(`[BOOKING APP] Admin login successful: ${email}`);
      res.json({ success: true });
    });
  } catch (error) {
    console.error('[BOOKING APP] Login error:', error);
    res.json({ success: false, error: 'Login failed' });
  }
});

/**
 * POST /api/admin/logout
 * Admin logout endpoint
 */
app.post('/api/admin/logout', (req, res) => {
  const email = req.session.adminEmail;
  req.session.destroy((err) => {
    if (err) {
      console.error('[BOOKING APP] Logout error:', err);
      return res.json({ success: false });
    }
    console.log(`[BOOKING APP] Admin logged out: ${email}`);
    res.json({ success: true });
  });
});

/**
 * GET /api/admin/check-auth
 * Check authentication status
 */
app.get('/api/admin/check-auth', (req, res) => {
  res.json({
    authenticated: !!(req.session && req.session.adminEmail),
    email: req.session?.adminEmail || null
  });
});

// ============================================================================
// USER MANAGEMENT API
// ============================================================================

/**
 * GET /api/admin/users
 * List all admin users
 */
app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, role, is_active, permissions, school_id, created_at, updated_at
      FROM admin_users
      WHERE school_id = 2
      ORDER BY created_at DESC
    `);
    res.json({ success: true, users: result.rows });
  } catch (error) {
    console.error('[USER MGMT] Error listing users:', error);
    res.status(500).json({ success: false, error: 'Failed to list users' });
  }
});

/**
 * POST /api/admin/users
 * Create a new admin user
 */
app.post('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    const { email, password, role = 'admin', can_access_booking = true, can_access_crm = true } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    // Check if user already exists
    const existing = await pool.query('SELECT id FROM admin_users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'User with this email already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO admin_users (email, password_hash, role, is_active, permissions, school_id, created_at, updated_at)
      VALUES ($1, $2, $3, true, $4, 2, NOW(), NOW())
      RETURNING id, email, role, is_active, permissions, created_at
    `, [
      email.toLowerCase(),
      passwordHash,
      role,
      JSON.stringify({ can_access_booking, can_access_crm })
    ]);

    console.log(`[USER MGMT] Created user: ${email}`);
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('[USER MGMT] Error creating user:', error);
    res.status(500).json({ success: false, error: 'Failed to create user' });
  }
});

/**
 * PUT /api/admin/users/:id
 * Update an admin user
 */
app.put('/api/admin/users/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, password, role, is_active, can_access_booking, can_access_crm } = req.body;

    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (email) {
      updates.push(`email = $${paramCount++}`);
      values.push(email.toLowerCase());
    }
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${paramCount++}`);
      values.push(passwordHash);
    }
    if (role) {
      updates.push(`role = $${paramCount++}`);
      values.push(role);
    }
    if (typeof is_active === 'boolean') {
      updates.push(`is_active = $${paramCount++}`);
      values.push(is_active);
    }
    if (typeof can_access_booking === 'boolean' || typeof can_access_crm === 'boolean') {
      // Get current permissions first
      const current = await pool.query('SELECT permissions FROM admin_users WHERE id = $1', [id]);
      const currentPerms = current.rows[0]?.permissions || {};
      const newPerms = {
        ...currentPerms,
        ...(typeof can_access_booking === 'boolean' ? { can_access_booking } : {}),
        ...(typeof can_access_crm === 'boolean' ? { can_access_crm } : {})
      };
      updates.push(`permissions = $${paramCount++}`);
      values.push(JSON.stringify(newPerms));
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await pool.query(`
      UPDATE admin_users
      SET ${updates.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, email, role, is_active, permissions, updated_at
    `, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    console.log(`[USER MGMT] Updated user ID: ${id}`);
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('[USER MGMT] Error updating user:', error);
    res.status(500).json({ success: false, error: 'Failed to update user' });
  }
});

/**
 * DELETE /api/admin/users/:id
 * Delete an admin user
 */
app.delete('/api/admin/users/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Don't allow deleting yourself
    const currentUser = await pool.query('SELECT id FROM admin_users WHERE email = $1', [req.session.adminEmail]);
    if (currentUser.rows[0]?.id === parseInt(id)) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }

    const result = await pool.query('DELETE FROM admin_users WHERE id = $1 RETURNING email', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    console.log(`[USER MGMT] Deleted user: ${result.rows[0].email}`);
    res.json({ success: true });
  } catch (error) {
    console.error('[USER MGMT] Error deleting user:', error);
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

/**
 * POST /api/admin/request-password-reset
 * Request password reset link
 */
app.post('/api/admin/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Get the CRM's school_id from environment variable
    const schoolSlug = process.env.SCHOOL_ID || 'more-house';
    const schoolResult = await pool.query(
      'SELECT id FROM schools WHERE slug = $1',
      [schoolSlug]
    );
    const crmSchoolId = schoolResult.rows[0]?.id;

    // Check if user exists (show users from this CRM's school + global admins)
    const userResult = await pool.query(
      'SELECT id, email FROM admin_users WHERE email = $1 AND is_active = $2 AND (school_id = $3 OR school_id IS NULL)',
      [email, true, crmSchoolId]
    );

    // Always return success to prevent email enumeration
    if (userResult.rows.length === 0) {
      return res.json({ success: true, message: 'If the email exists, a reset link will be sent.' });
    }

    const user = userResult.rows[0];

    // Generate reset token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save token
    await pool.query(`
      INSERT INTO password_reset_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
    `, [user.id, token, expiresAt]);

    // Determine reset link based on environment
    const baseUrl = process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com';
    const resetLink = `${baseUrl}/reset-password.html?token=${token}`;

    if (process.env.NODE_ENV === 'development') {
      // Development mode - log to console
      console.log(`Password reset token for ${user.email}: ${token}`);
      console.log(`Reset link: ${resetLink}`);
    }

    // Send email
    try {
      const schoolName = process.env.SCHOOL_NAME || 'More House School';

      await transporter.sendMail({
        from: process.env.EMAIL_FROM || `${schoolName} Booking <noreply@school.org>`,
        replyTo: process.env.GMAIL_USER,
        to: email,
        subject: 'Password Reset - SMART Booking',
        text: `Dear User,

We received a request to reset your password for SMART Booking System.

To reset your password, please click the following link or paste it into your browser:

${resetLink}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please disregard this email and your password will remain unchanged.

Best regards,
SMART Booking Team
${schoolName}
`,
        html: `
          <html>
          <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #091825;">Password Reset Request</h2>
            <p>Dear User,</p>
            <p>We received a request to reset your password for SMART Booking System.</p>
            <p>To reset your password, please click the button below:</p>
            <p style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" style="background-color: #FF9F1C; color: #091825; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Reset Password</a>
            </p>
            <p style="color: #666; font-size: 12px;">Or copy and paste this link: ${resetLink}</p>
            <p style="color: #FF9F1C; font-weight: bold;">Important: This link will expire in 1 hour for security reasons.</p>
            <p>If you did not request this password reset, please disregard this email and your password will remain unchanged.</p>
            <p style="margin-top: 30px; color: #666; font-size: 12px;">Best regards,<br>SMART Booking Team<br>${schoolName}</p>
          </body>
          </html>
        `
      });

      console.log(`✓ Password reset email sent to: ${email}`);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      // Don't reveal email sending failure to user for security
    }

    res.json({
      success: true,
      message: 'If the email exists, a reset link will be sent.'
    });
  } catch (error) {
    console.error('Request password reset error:', error);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

/**
 * POST /api/admin/reset-password
 * Reset password with token
 */
app.post('/api/admin/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Get token
    const tokenResult = await pool.query(`
      SELECT user_id, expires_at, used
      FROM password_reset_tokens
      WHERE token = $1
    `, [token]);

    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const resetToken = tokenResult.rows[0];

    if (resetToken.used) {
      return res.status(400).json({ error: 'Reset token has already been used' });
    }

    if (new Date() > new Date(resetToken.expires_at)) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query(
      'UPDATE admin_users SET password_hash = $1 WHERE id = $2',
      [passwordHash, resetToken.user_id]
    );

    // Mark token as used
    await pool.query(
      'UPDATE password_reset_tokens SET used = TRUE WHERE token = $1',
      [token]
    );

    console.log(`✓ Password reset successful for user ID: ${resetToken.user_id}`);

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== BOOKING SETTINGS ENDPOINTS ====================

// Get booking settings for a school
app.get('/api/booking-settings/:schoolId', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId } = req.params;

    const result = await pool.query(
      'SELECT * FROM booking_settings WHERE school_id = $1',
      [schoolId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Settings not found' });
    }

    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to get settings' });
  }
});

// Update booking settings
app.put('/api/booking-settings/:schoolId', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId } = req.params;
    const {
      tour_duration_options,
      default_tour_duration,
      booking_window_days,
      cancellation_window_hours,
      max_concurrent_tours,
      requires_approval,
      allow_waitlist,
      available_days,
      tour_start_time,
      tour_end_time,
      private_tour_enabled,
      private_tour_duration_minutes,
      private_tour_min_notice_days,
      private_tour_max_advance_days,
      private_tour_max_attendees,
      private_tour_buffer_minutes,
      private_tour_start_time,
      private_tour_end_time,
      has_prospectus_app,
      prospectus_url,
      school_name,
      logo_url,
      logo_size,
      form_heading,
      form_subtitle,
      primary_colour,
      secondary_colour
    } = req.body;

    const result = await pool.query(
      `UPDATE booking_settings SET
        tour_duration_options = $1,
        default_tour_duration = $2,
        booking_window_days = $3,
        cancellation_window_hours = $4,
        max_concurrent_tours = $5,
        requires_approval = $6,
        allow_waitlist = $7,
        available_days = $8,
        tour_start_time = $9,
        tour_end_time = $10,
        private_tour_enabled = $11,
        private_tour_duration_minutes = $12,
        private_tour_min_notice_days = $13,
        private_tour_max_advance_days = $14,
        private_tour_max_attendees = $15,
        private_tour_buffer_minutes = $16,
        private_tour_start_time = $17,
        private_tour_end_time = $18,
        has_prospectus_app = $19,
        prospectus_url = $20,
        school_name = $21,
        logo_url = $22,
        logo_size = $23,
        form_heading = $24,
        form_subtitle = $25,
        primary_colour = $26,
        secondary_colour = $27,
        updated_at = NOW()
      WHERE school_id = $28
      RETURNING *`,
      [
        tour_duration_options,
        default_tour_duration,
        booking_window_days,
        cancellation_window_hours,
        max_concurrent_tours,
        requires_approval,
        allow_waitlist,
        available_days,
        tour_start_time,
        tour_end_time,
        private_tour_enabled,
        private_tour_duration_minutes,
        private_tour_min_notice_days,
        private_tour_max_advance_days,
        private_tour_max_attendees,
        private_tour_buffer_minutes,
        private_tour_start_time,
        private_tour_end_time,
        has_prospectus_app,
        prospectus_url,
        school_name,
        logo_url,
        logo_size,
        form_heading,
        form_subtitle,
        primary_colour,
        secondary_colour,
        schoolId
      ]
    );

    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to update settings' });
  }
});

// ==================== EMAIL SETTINGS ENDPOINTS ====================

// Get email settings
app.get('/api/email-settings/:schoolId', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId } = req.params;

    const result = await pool.query(
      'SELECT smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, smtp_from_name, smtp_use_tls, reminder_days_before_1, reminder_days_before_2, followup_days_after, guide_reminder_days_before_1, guide_reminder_days_before_2 FROM booking_settings WHERE school_id = $1',
      [schoolId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Settings not found' });
    }

    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    console.error('Get email settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to get email settings' });
  }
});

// Update email settings
app.put('/api/email-settings/:schoolId', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId } = req.params;
    const { smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, smtp_from_name, smtp_use_tls, reminder_days_before_1, reminder_days_before_2, followup_days_after, guide_reminder_days_before_1, guide_reminder_days_before_2 } = req.body;

    const result = await pool.query(
      `UPDATE booking_settings
       SET smtp_host = $1, smtp_port = $2, smtp_username = $3, smtp_password = $4,
           smtp_from_email = $5, smtp_from_name = $6, smtp_use_tls = $7,
           reminder_days_before_1 = $8, reminder_days_before_2 = $9, followup_days_after = $10,
           guide_reminder_days_before_1 = $11, guide_reminder_days_before_2 = $12,
           updated_at = NOW()
       WHERE school_id = $13
       RETURNING *`,
      [smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, smtp_from_name, smtp_use_tls, reminder_days_before_1, reminder_days_before_2, followup_days_after, guide_reminder_days_before_1, guide_reminder_days_before_2, schoolId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Settings not found' });
    }

    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    console.error('Update email settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to update email settings' });
  }
});

// Test email settings
app.post('/api/email-settings/test', requireAdminAuth, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email, smtp_from_name, smtp_use_tls, test_email } = req.body;

    console.log('📧 Test email request received:', {
      smtp_host,
      smtp_port,
      smtp_username,
      smtp_from_email,
      test_email,
      smtp_use_tls
    });

    // Create a test transporter
    const testTransporter = nodemailer.createTransport({
      host: smtp_host,
      port: smtp_port,
      secure: smtp_port === 465, // true for 465, false for other ports
      auth: {
        user: smtp_username,
        pass: smtp_password
      },
      tls: {
        rejectUnauthorized: smtp_use_tls
      },
      connectionTimeout: 10000, // 10 seconds timeout
      greetingTimeout: 10000
    });

    console.log('📧 Verifying SMTP connection...');

    // Verify connection before sending
    await testTransporter.verify();
    console.log('✅ SMTP connection verified!');

    // Send test email
    await testTransporter.sendMail({
      from: `"${smtp_from_name}" <${smtp_from_email}>`,
      to: test_email,
      subject: 'Test Email from SMART Booking System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #091825;">Test Email Successful!</h2>
          <p>Your email settings are configured correctly.</p>
          <p><strong>Configuration:</strong></p>
          <ul>
            <li>SMTP Host: ${smtp_host}</li>
            <li>SMTP Port: ${smtp_port}</li>
            <li>Username: ${smtp_username}</li>
            <li>From: ${smtp_from_name} &lt;${smtp_from_email}&gt;</li>
            <li>TLS: ${smtp_use_tls ? 'Enabled' : 'Disabled'}</li>
          </ul>
          <p style="color: #6B7280; font-size: 0.875rem; margin-top: 2rem;">
            Powered by <span style="color: #FF9F1C; font-weight: 600;">bSMART</span> ai
          </p>
        </div>
      `
    });

    res.json({ success: true, message: 'Test email sent successfully' });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ success: false, error: error.message || 'Failed to send test email' });
  }
});

// ==================== EVENTS ENDPOINTS ====================

// Get all events for a school
app.get('/api/events', requireAdminOrApiKey, async (req, res) => {
  console.log('[API] GET /api/events - Query params:', req.query);
  try {
    const { schoolId, eventType, status, startDate, endDate, includeDeleted } = req.query;

    let query = 'SELECT * FROM events WHERE school_id = $1';
    const params = [schoolId];
    let paramCount = 1;

    // Exclude soft-deleted events unless specifically requested
    if (includeDeleted !== 'true') {
      query += ' AND (is_deleted IS NULL OR is_deleted = false)';
    }

    if (eventType) {
      paramCount++;
      query += ` AND event_type = $${paramCount}`;
      params.push(eventType);
    }

    if (status) {
      paramCount++;
      query += ` AND status = $${paramCount}`;
      params.push(status);
    }

    if (startDate) {
      paramCount++;
      query += ` AND event_date >= $${paramCount}`;
      params.push(startDate);
    }

    if (endDate) {
      paramCount++;
      query += ` AND event_date <= $${paramCount}`;
      params.push(endDate);
    }

    query += ' ORDER BY event_date ASC, start_time ASC';

    const result = await pool.query(query, params);
    res.json({ success: true, events: result.rows });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ success: false, error: 'Failed to get events' });
  }
});

// Get single event
app.get('/api/events/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM events WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }

    res.json({ success: true, event: result.rows[0] });
  } catch (error) {
    console.error('Get event error:', error);
    res.status(500).json({ success: false, error: 'Failed to get event' });
  }
});

// Create new event (No auth for now - accessed via iframe from authenticated admin dashboard)
app.post('/api/events', requireAdminAuth, async (req, res) => {
  try {
    const {
      school_id,
      event_type,
      title,
      description,
      event_date,
      start_time,
      end_time,
      location,
      max_capacity
    } = req.body;

    const result = await pool.query(
      `INSERT INTO events (
        school_id, event_type, title, description, event_date,
        start_time, end_time, location, max_capacity, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *`,
      [
        school_id,
        event_type,
        title,
        description,
        event_date,
        start_time,
        end_time,
        location,
        max_capacity,
        req.session.userId
      ]
    );

    res.json({ success: true, event: result.rows[0] });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ success: false, error: 'Failed to create event' });
  }
});

// Update event
app.put('/api/events/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      event_type,
      title,
      description,
      event_date,
      start_time,
      end_time,
      location,
      max_capacity,
      status
    } = req.body;

    // Validate required fields
    if (!title || !event_date || !start_time || !end_time) {
      return res.status(400).json({
        success: false,
        error: 'Required fields missing: title, event_date, start_time, end_time'
      });
    }

    const result = await pool.query(
      `UPDATE events SET
        event_type = $1,
        title = $2,
        description = $3,
        event_date = $4,
        start_time = $5,
        end_time = $6,
        location = $7,
        max_capacity = $8,
        status = $9,
        updated_at = NOW()
      WHERE id = $10
      RETURNING *`,
      [event_type, title, description, event_date, start_time, end_time, location, max_capacity, status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }

    res.json({ success: true, event: result.rows[0] });
  } catch (error) {
    console.error('Update event error:', error);
    res.status(500).json({ success: false, error: 'Failed to update event' });
  }
});

// Delete event
app.delete('/api/events/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Soft delete: set is_deleted flag instead of actually deleting
    await pool.query('UPDATE events SET is_deleted = true WHERE id = $1', [id]);
    res.json({ success: true, message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Delete event error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete event' });
  }
});

// ==================== INQUIRY ENDPOINTS ====================

// Get inquiry by ID (for pre-populating booking form)
app.get('/api/inquiry/:inquiryId', async (req, res) => {
  try {
    const { inquiryId } = req.params;

    const result = await pool.query(
      `SELECT
        id,
        parent_email,
        parent_name,
        contact_number,
        first_name,
        family_surname,
        age_group,
        entry_year,
        created_at
      FROM inquiries
      WHERE id = $1 AND deleted_at IS NULL
      LIMIT 1`,
      [inquiryId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Inquiry not found' });
    }

    res.json({
      success: true,
      inquiry: result.rows[0]
    });
  } catch (error) {
    console.error('Get inquiry error:', error);
    res.status(500).json({ success: false, error: 'Failed to get inquiry' });
  }
});

// ==================== PARENT VERIFICATION ENDPOINTS ====================

// Check if parent exists in enquiry database
app.post('/api/verify-parent', async (req, res) => {
  try {
    const { name, email, phone } = req.body;

    // Require at least ONE of: name, email, or phone
    if (!name && !email && !phone) {
      return res.status(400).json({ error: 'At least one of name, email, or phone is required' });
    }

    let query = `
      SELECT
        id as inquiry_id,
        parent_email,
        parent_name,
        contact_number,
        first_name,
        family_surname,
        age_group,
        entry_year,
        created_at
      FROM inquiries
      WHERE deleted_at IS NULL
    `;
    const params = [];
    let paramCount = 0;

    // Check name (case-insensitive partial match)
    if (name) {
      paramCount++;
      query += ` AND LOWER(parent_name) LIKE LOWER($${paramCount})`;
      params.push(`%${name}%`);
    }

    // Check email (case-insensitive exact match)
    if (email) {
      paramCount++;
      query += ` AND LOWER(parent_email) = LOWER($${paramCount})`;
      params.push(email);
    }

    // Check phone
    if (phone) {
      paramCount++;
      query += ` AND contact_number LIKE $${paramCount}`;
      params.push(`%${phone}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT 1`;

    const result = await pool.query(query, params);

    if (result.rows.length > 0) {
      res.json({
        found: true,
        parent: {
          email: result.rows[0].parent_email,
          name: result.rows[0].parent_name,
          inquiry_id: result.rows[0].inquiry_id,
          contact_number: result.rows[0].contact_number,
          first_name: result.rows[0].first_name,
          family_surname: result.rows[0].family_surname,
          age_group: result.rows[0].age_group,
          entry_year: result.rows[0].entry_year,
          registered_at: result.rows[0].created_at
        }
      });
    } else {
      res.json({ found: false });
    }
  } catch (error) {
    console.error('Parent verification error:', error);
    res.status(500).json({ error: 'Failed to verify parent information' });
  }
});

// ==================== BOOKINGS ENDPOINTS ====================

// Get all bookings
app.get('/api/bookings', requireAdminAuth, async (req, res) => {
  console.log('[API] GET /api/bookings - Query params:', req.query);
  try {
    const { schoolId, eventId, status, startDate, endDate } = req.query;

    let query = `
      SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
             tg.name as guide_name,
             i.age_group, i.entry_year, i.sciences, i.mathematics, i.english, i.languages, i.humanities,
             i.business, i.drama, i.music, i.art, i.creative_writing, i.sport,
             i.leadership, i.community_service, i.outdoor_education, i.academic_excellence,
             i.pastoral_care, i.university_preparation, i.personal_development,
             i.career_guidance, i.extracurricular_opportunities,
             EXISTS(SELECT 1 FROM feedback_responses WHERE booking_id = b.id) as feedback_submitted
      FROM bookings b
      LEFT JOIN events e ON b.event_id = e.id
      LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
      LEFT JOIN inquiries i ON (b.inquiry_id = i.id OR (b.email = i.parent_email AND i.first_name = b.student_first_name))
      WHERE b.school_id = $1
    `;
    const params = [schoolId];
    let paramCount = 1;

    if (eventId) {
      paramCount++;
      query += ` AND b.event_id = $${paramCount}`;
      params.push(eventId);
    }

    if (status) {
      paramCount++;
      query += ` AND b.status = $${paramCount}`;
      params.push(status);
    }

    if (startDate) {
      paramCount++;
      query += ` AND e.event_date >= $${paramCount}`;
      params.push(startDate);
    }

    if (endDate) {
      paramCount++;
      query += ` AND e.event_date <= $${paramCount}`;
      params.push(endDate);
    }

    query += ' ORDER BY b.id, b.booked_at DESC';

    const result = await pool.query(query, params);
    res.json({ success: true, bookings: result.rows });
  } catch (error) {
    console.error('Get bookings error:', error);
    res.status(500).json({ success: false, error: 'Failed to get bookings' });
  }
});

// Get single booking
app.get('/api/bookings/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT b.*, e.title as event_title, e.event_date, e.start_time, e.end_time,
              tg.name as guide_name, i.age_group
       FROM bookings b
       LEFT JOIN events e ON b.event_id = e.id
       LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
       LEFT JOIN inquiries i ON b.inquiry_id = i.id
       WHERE b.id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('Get booking error:', error);
    res.status(500).json({ success: false, error: 'Failed to get booking' });
  }
});

// Create new booking (Public endpoint)
app.post('/api/bookings', requireAdminOrApiKey, async (req, res) => {
  console.log('[CREATE BOOKING] Received request body:', JSON.stringify(req.body, null, 2));
  try {
    const {
      school_id,
      event_id,
      inquiry_id,
      parent_first_name,
      parent_last_name,
      email,
      phone,
      student_first_name,
      student_last_name,
      num_attendees,
      special_requirements,
      preferred_language,
      booking_type,
      preferred_date,
      preferred_time
    } = req.body;

    console.log('[CREATE BOOKING] Parsed data:', {
      school_id,
      event_id,
      inquiry_id,
      parent_first_name,
      parent_last_name,
      email,
      phone,
      student_first_name,
      student_last_name,
      booking_type,
      num_attendees
    });

    // Cross-check parent details against inquiries database
    let matchedInquiry = null;
    const parentFullName = `${parent_first_name} ${parent_last_name}`.trim();

    if (email && phone && parentFullName) {
      try {
        let inquiryQuery = `
          SELECT id, parent_email, parent_name, contact_number, first_name, family_surname
          FROM inquiries
          WHERE deleted_at IS NULL
        `;
        const inquiryParams = [];
        let paramCount = 0;

        // Check parent name (partial match)
        paramCount++;
        inquiryQuery += ` AND LOWER(parent_name) LIKE LOWER($${paramCount})`;
        inquiryParams.push(`%${parentFullName}%`);

        // Check email
        paramCount++;
        inquiryQuery += ` AND LOWER(parent_email) = LOWER($${paramCount})`;
        inquiryParams.push(email);

        // Check phone
        paramCount++;
        inquiryQuery += ` AND contact_number LIKE $${paramCount}`;
        inquiryParams.push(`%${phone}%`);

        inquiryQuery += ` ORDER BY created_at DESC LIMIT 1`;

        const inquiryResult = await pool.query(inquiryQuery, inquiryParams);

        if (inquiryResult.rows.length > 0) {
          matchedInquiry = inquiryResult.rows[0];
          console.log('Matched inquiry found:', matchedInquiry.id, 'for booking by', parentFullName, email);
        } else {
          console.log('No matching inquiry found for', parentFullName, email, phone);
        }
      } catch (error) {
        console.error('Error checking inquiries:', error);
        // Continue with booking even if inquiry check fails
      }
    }

    // Get booking settings
    const settingsResult = await pool.query(
      'SELECT * FROM booking_settings WHERE school_id = $1',
      [school_id]
    );
    const settings = settingsResult.rows[0] || { requires_approval: false };

    // For private tours and taster days, event_id is optional
    let event = null;
    let initialStatus = settings.requires_approval ? 'pending' : 'confirmed';

    if (booking_type === 'private_tour' || booking_type === 'taster_day') {
      // Private tours and taster days always start as pending (admin must schedule them)
      initialStatus = 'pending';
    } else {
      // Get event details for open day bookings
      if (!event_id) {
        return res.status(400).json({ success: false, error: 'Event ID is required for open day bookings' });
      }

      const eventResult = await pool.query(
        'SELECT * FROM events WHERE id = $1 AND school_id = $2',
        [event_id, school_id]
      );

      if (eventResult.rows.length === 0) {
        return res.status(404).json({ success: false, error: 'Event not found' });
      }

      event = eventResult.rows[0];

      // Check capacity
      if (event.current_bookings + num_attendees > event.max_capacity) {
        return res.status(400).json({ success: false, error: 'Event is fully booked' });
      }

      // Determine initial status based on settings
      initialStatus = settings.requires_approval ? 'pending' : 'confirmed';
    }

    // Generate cancellation token and feedback token
    const cancellationToken = crypto.randomBytes(32).toString('hex');
    const feedbackToken = crypto.randomBytes(32).toString('hex');

    // Use matched inquiry ID if found, otherwise use the one provided
    const finalInquiryId = matchedInquiry ? matchedInquiry.id : inquiry_id;

    // Create booking
    const bookingResult = await pool.query(
      `INSERT INTO bookings (
        school_id, event_id, inquiry_id, parent_first_name, parent_last_name,
        email, phone, student_first_name, student_last_name,
        num_attendees, special_requirements, preferred_language,
        booking_type, status, cancellation_token, feedback_token,
        scheduled_date, scheduled_time
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *`,
      [
        school_id, event_id, finalInquiryId, parent_first_name, parent_last_name,
        email, phone, student_first_name, student_last_name,
        num_attendees, special_requirements, preferred_language,
        booking_type, initialStatus, cancellationToken, feedbackToken,
        preferred_date || null, preferred_time || null
      ]
    );

    const booking = bookingResult.rows[0];

    // Update event booking count (only for open day bookings with events)
    if (booking_type === 'open_day' && event_id) {
      await pool.query(
        'UPDATE events SET current_bookings = current_bookings + $1 WHERE id = $2',
        [num_attendees, event_id]
      );
    }

    // Update inquiry record to mark that they've booked
    if (finalInquiryId) {
      try {
        if (booking_type === 'open_day') {
          await pool.query(
            `UPDATE inquiries SET
              open_day_booked = true,
              open_day_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              booking_event_id = $3,
              priority = true
            WHERE id = $1`,
            [finalInquiryId, 'open_day', event_id]
          );
          console.log(`Marked inquiry ${finalInquiryId} as having booked an open day`);
        } else if (booking_type === 'private_tour') {
          await pool.query(
            `UPDATE inquiries SET
              tour_booked = true,
              tour_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              booking_event_id = NULL,
              priority = true
            WHERE id = $1`,
            [finalInquiryId, 'private_tour']
          );
          console.log(`Marked inquiry ${finalInquiryId} as having booked a private tour`);
        } else if (booking_type === 'taster_day') {
          await pool.query(
            `UPDATE inquiries SET
              tour_booked = true,
              tour_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              booking_event_id = NULL,
              priority = true
            WHERE id = $1`,
            [finalInquiryId, 'taster_day']
          );
          console.log(`Marked inquiry ${finalInquiryId} as having booked a taster day`);
        }
      } catch (error) {
        console.error('Error updating inquiry booking status:', error);
        // Don't fail the booking if inquiry update fails
      }
    }

    // Send email based on booking status
    try {
      // For pending bookings (private tours and taster days), send "pending approval" email
      // For confirmed bookings (open days), send "confirmation" email
      const emailTemplateType = initialStatus === 'pending' ? 'booking_pending' : 'booking_confirmation';
      const templateId = await getTemplateId(booking_type, emailTemplateType, school_id);

      if (templateId) {
        // Use the template-based email system
        await sendTemplateEmail(booking, templateId, emailTemplateType);
        console.log(`✅ Booking ${emailTemplateType} email sent using template ID ${templateId}`);
      } else {
        console.error(`❌ No email template found for booking_type: ${booking_type}, template_type: ${emailTemplateType}`);
      }
    } catch (emailError) {
      console.error('Email send error:', emailError);
      // Don't fail the booking if email fails
    }

    // Send notification to admissions team (async, don't wait)
    sendAdmissionsBookingNotification(booking).catch(err => {
      console.error('Error sending admissions notification:', err);
    });

    res.json({ success: true, booking, status: initialStatus });
  } catch (error) {
    console.error('Create booking error:', error);
    res.status(500).json({ success: false, error: 'Failed to create booking' });
  }
});

// Update booking details
app.put('/api/bookings/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`[UPDATE BOOKING] Received request to update booking #${id}`);
    console.log('[UPDATE BOOKING] Request body:', req.body);

    const {
      parent_first_name,
      parent_last_name,
      email,
      phone,
      student_first_name,
      student_last_name,
      num_attendees,
      special_requirements,
      preferred_language,
      assigned_guide_id
    } = req.body;

    // Validate required fields
    if (!parent_first_name || !parent_last_name || !email || !phone || !student_first_name || !num_attendees) {
      console.log('[UPDATE BOOKING] Validation failed - missing required fields');
      return res.status(400).json({ success: false, error: 'Required fields are missing' });
    }

    // Update the booking
    const result = await pool.query(
      `UPDATE bookings SET
        parent_first_name = $1,
        parent_last_name = $2,
        email = $3,
        phone = $4,
        student_first_name = $5,
        student_last_name = $6,
        num_attendees = $7,
        special_requirements = $8,
        preferred_language = $9,
        assigned_guide_id = $10,
        updated_at = NOW()
      WHERE id = $11
      RETURNING *`,
      [
        parent_first_name,
        parent_last_name,
        email,
        phone,
        student_first_name,
        student_last_name,
        num_attendees,
        special_requirements,
        preferred_language,
        assigned_guide_id,
        id
      ]
    );

    if (result.rows.length === 0) {
      console.log('[UPDATE BOOKING] Booking not found');
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const updatedBooking = result.rows[0];

    // Also update the linked inquiry record if it exists
    if (updatedBooking.inquiry_id) {
      try {
        await pool.query(
          `UPDATE inquiries SET
            parent_name = $1,
            parent_email = $2,
            contact_number = $3,
            first_name = $4,
            family_surname = $5,
            updated_at = NOW()
          WHERE id = $6`,
          [
            `${parent_first_name} ${parent_last_name}`,
            email,
            phone,
            student_first_name,
            student_last_name,
            updatedBooking.inquiry_id
          ]
        );
        console.log('[UPDATE BOOKING] Also updated linked inquiry record');
      } catch (inquiryError) {
        console.warn('[UPDATE BOOKING] Could not update inquiry:', inquiryError.message);
      }
    }

    console.log('[UPDATE BOOKING] Successfully updated booking');
    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('[UPDATE BOOKING] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to update booking' });
  }
});

// Staff-initiated booking creation (from CRM)
app.post('/api/bookings/staff-create', requireAdminOrApiKey, async (req, res) => {
  console.log('[STAFF CREATE BOOKING] Received request:', JSON.stringify(req.body, null, 2));
  try {
    const {
      bookingType,
      eventId,
      scheduledDate,
      scheduledTime,
      numAttendees,
      specialRequirements,
      inquiryId,
      schoolId,
      parentFirstName,
      parentLastName,
      email,
      phone,
      studentFirstName,
      studentLastName,
      assignedGuideId
    } = req.body;

    // Validate required fields
    if (!bookingType || !schoolId || !email) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    // Generate tokens
    const cancellationToken = crypto.randomBytes(32).toString('hex');
    const feedbackToken = crypto.randomBytes(32).toString('hex');

    // Determine initial status - staff bookings are auto-confirmed
    let initialStatus = 'confirmed';
    let finalEventId = eventId || null;
    let finalScheduledDate = scheduledDate || null;
    let finalScheduledTime = scheduledTime || null;

    // For open_day bookings, validate event exists
    if (bookingType === 'open_day') {
      if (!eventId) {
        return res.status(400).json({ success: false, error: 'Event ID required for open day bookings' });
      }

      const eventResult = await pool.query(
        'SELECT * FROM events WHERE id = $1 AND school_id = $2',
        [eventId, schoolId]
      );

      if (eventResult.rows.length === 0) {
        return res.status(404).json({ success: false, error: 'Event not found' });
      }

      const event = eventResult.rows[0];

      // Check capacity
      const attendeeCount = numAttendees || 1;
      if (event.current_bookings + attendeeCount > event.max_capacity) {
        return res.status(400).json({ success: false, error: 'Event is fully booked' });
      }

      // Update event booking count
      await pool.query(
        'UPDATE events SET current_bookings = current_bookings + $1 WHERE id = $2',
        [attendeeCount, eventId]
      );
    }

    // Create booking
    const bookingResult = await pool.query(
      `INSERT INTO bookings (
        school_id, event_id, inquiry_id, parent_first_name, parent_last_name,
        email, phone, student_first_name, student_last_name,
        num_attendees, special_requirements,
        booking_type, status, cancellation_token, feedback_token,
        scheduled_date, scheduled_time, assigned_guide_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *`,
      [
        schoolId, finalEventId, inquiryId, parentFirstName, parentLastName,
        email, phone, studentFirstName, studentLastName,
        numAttendees || 1, specialRequirements || null,
        bookingType, initialStatus, cancellationToken, feedbackToken,
        finalScheduledDate, finalScheduledTime, assignedGuideId || null
      ]
    );

    const booking = bookingResult.rows[0];

    // Update inquiry record
    if (inquiryId) {
      try {
        if (bookingType === 'open_day') {
          await pool.query(
            `UPDATE inquiries SET
              open_day_booked = true,
              open_day_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              booking_event_id = $3,
              priority = true,
              status = 'open-day-booked'
            WHERE id = $1`,
            [inquiryId, 'open_day', eventId]
          );
        } else if (bookingType === 'private_tour') {
          await pool.query(
            `UPDATE inquiries SET
              tour_booked = true,
              tour_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              priority = true,
              status = 'tour-booked'
            WHERE id = $1`,
            [inquiryId, 'private_tour']
          );
        } else if (bookingType === 'taster_day') {
          await pool.query(
            `UPDATE inquiries SET
              tour_booked = true,
              tour_booked_at = NOW(),
              has_booking = true,
              booking_type = $2,
              priority = true,
              status = 'taster-day'
            WHERE id = $1`,
            [inquiryId, 'taster_day']
          );
        }
      } catch (updateError) {
        console.error('Error updating inquiry:', updateError);
        // Continue even if inquiry update fails
      }
    }

    // Send confirmation email
    try {
      let event = null;
      if (finalEventId) {
        const eventResult = await pool.query('SELECT * FROM events WHERE id = $1', [finalEventId]);
        event = eventResult.rows[0];
      }

      const eventTitle = event ? event.title : (bookingType === 'private_tour' ? 'Private Tour' : bookingType === 'taster_day' ? 'Taster Day' : 'Your Booking');
      let emailText, emailHTML;

      if (bookingType === 'private_tour') {
        emailText = `Dear ${parentFirstName} ${parentLastName},

Thank you for your private tour booking.

Your booking has been confirmed by our admissions team.

Booking Details:
- Type: Private Tour
- Date: ${finalScheduledDate || 'To be confirmed'}
- Time: ${finalScheduledTime || 'To be confirmed'}
- Number of Attendees: ${numAttendees || 1}
${studentFirstName ? `- Student: ${studentFirstName} ${studentLastName}\n` : ''}

If you need to make changes or have questions, please reply to this email.

Best regards,
More House School Admissions Team`;

        emailHTML = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Your Private Tour Booking Confirmed</h2>
            <p>Dear ${parentFirstName} ${parentLastName},</p>
            <p>Your private tour booking has been <strong>confirmed</strong> by our admissions team.</p>

            <h3 style="color: #091825;">Booking Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Type:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">Private Tour</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Date:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${finalScheduledDate || 'To be confirmed'}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Time:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${finalScheduledTime || 'To be confirmed'}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Attendees:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${numAttendees || 1}</td></tr>
              ${studentFirstName ? `<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Student:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${studentFirstName} ${studentLastName}</td></tr>` : ''}
            </table>

            <p style="margin-top: 20px;">If you need to make changes or have questions, please reply to this email.</p>

            <p style="margin-top: 30px; color: #666; font-size: 14px;">
              Best regards,<br>
              More House School<br>
              Admissions Team
            </p>
          </div>
        `;
      } else if (event) {
        emailText = `Dear ${parentFirstName} ${parentLastName},

Thank you for booking ${event.title}.

Your booking has been confirmed.

Booking Details:
- Event: ${event.title}
- Date: ${event.event_date}
- Time: ${event.start_time} - ${event.end_time}
- Location: ${event.location || 'TBC'}
- Number of Attendees: ${numAttendees || 1}
${studentFirstName ? `- Student: ${studentFirstName} ${studentLastName}\n` : ''}

If you need to cancel or reschedule, please reply to this email.

Best regards,
More House School Admissions Team`;

        emailHTML = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Booking Confirmed</h2>
            <p>Dear ${parentFirstName} ${parentLastName},</p>
            <p>Your booking for <strong>${event.title}</strong> has been confirmed.</p>

            <h3 style="color: #091825;">Booking Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Event:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${event.title}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Date:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${event.event_date}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Time:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${event.start_time} - ${event.end_time}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Location:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${event.location || 'TBC'}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Attendees:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${numAttendees || 1}</td></tr>
              ${studentFirstName ? `<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Student:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${studentFirstName} ${studentLastName}</td></tr>` : ''}
            </table>

            <p style="margin-top: 20px;">If you need to cancel or reschedule your booking, please reply to this email.</p>

            <p style="margin-top: 30px; color: #666; font-size: 14px;">
              Best regards,<br>
              More House School<br>
              Admissions Team
            </p>
          </div>
        `;
      } else {
        // Taster day without event
        emailText = `Dear ${parentFirstName} ${parentLastName},

Thank you for your taster day booking.

Your booking has been confirmed.

Booking Details:
- Type: Taster Day
- Date: ${finalScheduledDate || 'To be confirmed'}
- Time: ${finalScheduledTime || 'To be confirmed'}
- Number of Attendees: ${numAttendees || 1}
${studentFirstName ? `- Student: ${studentFirstName} ${studentLastName}\n` : ''}

If you need to make changes or have questions, please reply to this email.

Best regards,
More House School Admissions Team`;

        emailHTML = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Taster Day Booking Confirmed</h2>
            <p>Dear ${parentFirstName} ${parentLastName},</p>
            <p>Your taster day booking has been <strong>confirmed</strong>.</p>

            <h3 style="color: #091825;">Booking Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Type:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">Taster Day</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Date:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${finalScheduledDate || 'To be confirmed'}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Time:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${finalScheduledTime || 'To be confirmed'}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Attendees:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${numAttendees || 1}</td></tr>
              ${studentFirstName ? `<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Student:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${studentFirstName} ${studentLastName}</td></tr>` : ''}
            </table>

            <p style="margin-top: 20px;">If you need to make changes or have questions, please reply to this email.</p>

            <p style="margin-top: 30px; color: #666; font-size: 14px;">
              Best regards,<br>
              More House School<br>
              Admissions Team
            </p>
          </div>
        `;
      }

      const emailSubject = `More House School - ${eventTitle} Confirmation`;

      // Send via email worker for branded template
      await emailWorker.sendEmail({
        to: email,
        subject: emailSubject,
        text: emailText,
        html: emailHTML
      });

      // Log email
      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'staff_confirmation', email, emailSubject]
      );

      console.log(`[STAFF CREATE BOOKING] Confirmation email sent to ${email}`);
    } catch (emailError) {
      console.error('[STAFF CREATE BOOKING] Email send error:', emailError);
      // Don't fail the booking if email fails
    }

    console.log('[STAFF CREATE BOOKING] Successfully created booking:', booking.id);
    res.json({ success: true, booking: booking });

  } catch (error) {
    console.error('[STAFF CREATE BOOKING] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to create booking: ' + error.message });
  }
});

// Update booking (for staff edits)
app.put('/api/bookings/:id/staff-edit', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { scheduled_date, scheduled_time, status } = req.body;

    console.log(`[STAFF EDIT BOOKING] Booking #${id}:`, { scheduled_date, scheduled_time, status });

    const result = await pool.query(
      `UPDATE bookings SET
        scheduled_date = COALESCE($1, scheduled_date),
        scheduled_time = COALESCE($2, scheduled_time),
        status = COALESCE($3, status),
        updated_at = NOW()
      WHERE id = $4
      RETURNING *`,
      [scheduled_date, scheduled_time, status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    console.log(`[STAFF EDIT BOOKING] Successfully updated booking #${id}`);
    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('[UPDATE BOOKING] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to update booking: ' + error.message });
  }
});

// Reassign tour guide and send notification emails
app.post('/api/bookings/:id/reassign-guide', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { oldGuideId, newGuideId } = req.body;

    console.log(`[REASSIGN GUIDE] Booking #${id}: Old guide ${oldGuideId} -> New guide ${newGuideId}`);

    // Generate feedback token if assigning a new guide and no token exists
    if (newGuideId) {
      const feedbackToken = crypto.randomBytes(32).toString('hex');
      await pool.query(
        `UPDATE bookings SET
          feedback_token = COALESCE(feedback_token, $1),
          updated_at = NOW()
        WHERE id = $2`,
        [feedbackToken, id]
      );
    }

    // Get full booking details (including newly generated feedback_token)
    const bookingRes = await pool.query(
      `SELECT b.*, e.title as event_title, e.event_date, e.start_time,
              i.age_group, i.entry_year, i.sciences, i.mathematics, i.english, i.languages, i.humanities,
              i.business, i.drama, i.music, i.art, i.creative_writing, i.sport,
              i.leadership, i.community_service, i.outdoor_education, i.academic_excellence,
              i.pastoral_care, i.university_preparation, i.personal_development,
              i.career_guidance, i.extracurricular_opportunities
       FROM bookings b
       LEFT JOIN events e ON b.event_id = e.id
       LEFT JOIN inquiries i ON b.inquiry_id = i.id
       WHERE b.id = $1`,
      [id]
    );

    if (bookingRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = bookingRes.rows[0];

    // Helper function to send tour guide email
    const sendGuideEmail = async (guideId, isNew) => {
      if (!guideId) return;

      const guideRes = await pool.query(
        'SELECT * FROM tour_guides WHERE id = $1',
        [guideId]
      );

      if (guideRes.rows.length === 0) return;

      const guide = guideRes.rows[0];
      if (!guide.email) return;

      const templateType = isNew ? 'guide_assigned' : 'guide_removed';
      const subject = isNew
        ? `New Tour Assignment: ${booking.parent_first_name} ${booking.parent_last_name}`
        : `Tour Assignment Removed: ${booking.parent_first_name} ${booking.parent_last_name}`;

      // Fetch AI Summary
      let aiSummary = null;
      if (booking.inquiry_id) {
        const summaryRes = await pool.query(
          `SELECT summary_text, recommendations, insights
           FROM ai_summaries
           WHERE inquiry_id = $1 AND summary_type = 'overall'
           ORDER BY generated_at DESC
           LIMIT 1`,
          [booking.inquiry_id]
        );
        if (summaryRes.rows.length > 0) {
          const summary = summaryRes.rows[0];
          aiSummary = {
            overview: summary.summary_text,
            recommendations: summary.recommendations,
            strategy: summary.insights?.strategy || null
          };
        }
      }

      // Fetch email history
      let emailHistory = [];
      if (booking.inquiry_id) {
        const emailRes = await pool.query(
          `SELECT template_type, parent_name, created_at, ai_service, generated_email, original_email_text
           FROM email_generation_history
           WHERE inquiry_id = $1
           ORDER BY created_at DESC
           LIMIT 10`,
          [booking.inquiry_id]
        );
        emailHistory = emailRes.rows;
      }

      // Fetch booking notes
      const notesRes = await pool.query(
        `SELECT bn.note, bn.created_at, CONCAT(au.first_name, ' ', au.last_name) as created_by_name
         FROM booking_notes bn
         LEFT JOIN admin_users au ON bn.created_by = au.id
         WHERE bn.booking_id = $1
         ORDER BY bn.created_at DESC
         LIMIT 10`,
        [booking.id]
      );
      const notes = notesRes.rows;

      // Fetch session history
      let sessions = [];
      let moduleViews = [];
      if (booking.inquiry_id) {
        const sessionRes = await pool.query(
          `SELECT start_time, duration_seconds, engagement_score, sections_visited, videos_played
           FROM session_summaries
           WHERE inquiry_id = $1
           ORDER BY start_time DESC
           LIMIT 5`,
          [booking.inquiry_id]
        );
        sessions = sessionRes.rows;

        const moduleRes = await pool.query(
          `SELECT module_name, started_at, time_spent_seconds, scroll_depth_percent
           FROM module_view_sessions
           WHERE enquiry_id = $1
           ORDER BY started_at DESC
           LIMIT 10`,
          [booking.inquiry_id]
        );
        moduleViews = moduleRes.rows;
      }

      // Build comprehensive email with ALL booking details - show everything with checkmarks

      const body = `
        <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f9f9f9;">
          <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="color: #091825; border-bottom: 3px solid #FF9F1C; padding-bottom: 10px;">
              ${isNew ? 'New Tour Assignment' : 'Tour Assignment Removed'}
            </h2>

            <div style="background: #F0F9FF; padding: 20px; border-left: 4px solid #034674; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #034674;">Booking Information</h3>
              <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0;"><strong>Booking ID:</strong></td><td>#${booking.id}</td></tr>
                <tr><td style="padding: 8px 0;"><strong>Type:</strong></td><td>${booking.booking_type === 'open_day' ? 'Open Day' : booking.booking_type === 'taster_day' ? 'Taster Day' : 'Private Tour'}</td></tr>
                <tr><td style="padding: 8px 0;"><strong>Status:</strong></td><td>${booking.status.toUpperCase()}</td></tr>
                ${booking.event_title ? `<tr><td style="padding: 8px 0;"><strong>Event:</strong></td><td>${booking.event_title}</td></tr>` : ''}
                ${booking.event_date ? `<tr><td style="padding: 8px 0;"><strong>Date:</strong></td><td>${new Date(booking.event_date).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</td></tr>` : ''}
                ${booking.start_time ? `<tr><td style="padding: 8px 0;"><strong>Time:</strong></td><td>${booking.start_time}</td></tr>` : ''}
                ${booking.scheduled_date ? `<tr><td style="padding: 8px 0;"><strong>Scheduled:</strong></td><td>${new Date(booking.scheduled_date).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at ${booking.scheduled_time || 'TBC'}</td></tr>` : ''}
                <tr><td style="padding: 8px 0;"><strong>Booked At:</strong></td><td>${new Date(booking.booked_at).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</td></tr>
              </table>
            </div>

            <div style="background: #FFF9F0; padding: 20px; border-left: 4px solid #FF9F1C; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #FF9F1C;">Family Contact Information</h3>
              <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0;"><strong>Parent Name:</strong></td><td>${booking.parent_first_name} ${booking.parent_last_name}</td></tr>
                <tr><td style="padding: 8px 0;"><strong>Email:</strong></td><td><a href="mailto:${booking.email}">${booking.email}</a></td></tr>
                <tr><td style="padding: 8px 0;"><strong>Phone:</strong></td><td><a href="tel:${booking.phone}">${booking.phone}</a></td></tr>
                <tr><td style="padding: 8px 0;"><strong>Number of Attendees:</strong></td><td>${booking.num_attendees}</td></tr>
                ${booking.preferred_language ? `<tr><td style="padding: 8px 0;"><strong>Preferred Language:</strong></td><td>${booking.preferred_language}</td></tr>` : ''}
              </table>
            </div>

            <div style="background: #F0FFF4; padding: 20px; border-left: 4px solid #10B981; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #10B981;">Student Information</h3>
              <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0;"><strong>Student Name:</strong></td><td>${booking.student_first_name} ${booking.student_last_name || ''}</td></tr>
                ${booking.age_group ? `<tr><td style="padding: 8px 0;"><strong>Age Group:</strong></td><td>${booking.age_group}</td></tr>` : ''}
                ${booking.entry_year ? `<tr><td style="padding: 8px 0;"><strong>Entry Year:</strong></td><td>${booking.entry_year}</td></tr>` : ''}
              </table>
            </div>

            ${(() => {
              const subjects = [];
              if (booking.sciences) subjects.push('Sciences');
              if (booking.mathematics) subjects.push('Mathematics');
              if (booking.english) subjects.push('English');
              if (booking.languages) subjects.push('Languages');
              if (booking.humanities) subjects.push('Humanities');
              if (booking.business) subjects.push('Business');
              if (booking.drama) subjects.push('Drama');
              if (booking.music) subjects.push('Music');
              if (booking.art) subjects.push('Art');
              if (booking.creative_writing) subjects.push('Creative Writing');
              if (booking.sport) subjects.push('Sport');

              return subjects.length > 0 ? `
            <div style="background: #FFF0F5; padding: 20px; border-left: 4px solid #EC4899; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #EC4899;">Subject Interests</h3>
              <ul style="margin: 0; padding-left: 20px;">
                ${subjects.map(s => `<li style="padding: 4px 0;">${s}</li>`).join('')}
              </ul>
            </div>
              ` : '';
            })()}

            ${(() => {
              const priorities = [];
              if (booking.leadership) priorities.push('Leadership');
              if (booking.community_service) priorities.push('Community Service');
              if (booking.outdoor_education) priorities.push('Outdoor Education');
              if (booking.academic_excellence) priorities.push('Academic Excellence');
              if (booking.pastoral_care) priorities.push('Pastoral Care');
              if (booking.university_preparation) priorities.push('University Preparation');
              if (booking.personal_development) priorities.push('Personal Development');
              if (booking.career_guidance) priorities.push('Career Guidance');
              if (booking.extracurricular_opportunities) priorities.push('Extracurricular Opportunities');

              return priorities.length > 0 ? `
            <div style="background: #F5F0FF; padding: 20px; border-left: 4px solid #8B5CF6; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #8B5CF6;">Family Priorities & Values</h3>
              <ul style="margin: 0; padding-left: 20px;">
                ${priorities.map(p => `<li style="padding: 4px 0;">${p}</li>`).join('')}
              </ul>
            </div>
              ` : '';
            })()}

            ${booking.special_requirements ? `
            <div style="background: #FFFBEB; padding: 20px; border-left: 4px solid #F59E0B; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #F59E0B;">Special Requirements</h3>
              <p style="margin: 0; white-space: pre-wrap;">${booking.special_requirements}</p>
            </div>
            ` : ''}

            ${aiSummary ? `
            <div style="background: #ECFDF5; padding: 20px; border-left: 4px solid #10B981; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #10B981;">SMART AI Summary & Recommendations</h3>
              ${aiSummary.overview ? `
                <div style="margin-bottom: 15px;">
                  <p style="margin: 0 0 5px 0; font-size: 13px; font-weight: 600; color: #065F46;">Overview:</p>
                  <div style="background: white; padding: 12px; border-radius: 4px; font-size: 13px; line-height: 1.6;">${aiSummary.overview}</div>
                </div>
              ` : ''}
              ${aiSummary.recommendations && aiSummary.recommendations.length > 0 ? `
                <div style="margin-bottom: 15px;">
                  <p style="margin: 0 0 5px 0; font-size: 13px; font-weight: 600; color: #065F46;">Recommended Actions:</p>
                  <ul style="margin: 0; padding-left: 20px; background: white; padding: 12px 12px 12px 32px; border-radius: 4px;">
                    ${aiSummary.recommendations.map(r => `<li style="padding: 4px 0; font-size: 13px; line-height: 1.6;">${r}</li>`).join('')}
                  </ul>
                </div>
              ` : ''}
              ${aiSummary.strategy ? `
                <div>
                  <p style="margin: 0 0 5px 0; font-size: 13px; font-weight: 600; color: #065F46;">Engagement Strategy:</p>
                  <div style="background: white; padding: 12px; border-radius: 4px; font-size: 13px; line-height: 1.6;">${aiSummary.strategy}</div>
                </div>
              ` : ''}
            </div>
            ` : ''}

            ${notes.length > 0 ? `
            <div style="background: #F0F9FF; padding: 20px; border-left: 4px solid #0284C7; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #0284C7;">Admin Notes</h3>
              ${notes.map(note => `
                <div style="background: white; padding: 12px; margin-bottom: 10px; border-radius: 4px; border: 1px solid #E0F2FE;">
                  <p style="margin: 0; font-size: 14px;">${note.note.replace(/\n/g, '<br>')}</p>
                  <p style="margin: 8px 0 0 0; font-size: 12px; color: #666;">
                    <strong>${note.created_by_name || 'Admin'}</strong> • ${new Date(note.created_at).toLocaleString('en-GB')}
                  </p>
                </div>
              `).join('')}
            </div>
            ` : ''}

            ${emailHistory.length > 0 ? `
            <div style="background: #FEF3C7; padding: 20px; border-left: 4px solid #F59E0B; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #F59E0B;">Email History</h3>
              ${emailHistory.map((email, idx) => `
                <div style="background: white; padding: 15px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #FDE68A;">
                  <div style="border-bottom: 1px solid #FDE68A; padding-bottom: 10px; margin-bottom: 10px;">
                    <p style="margin: 0; font-size: 14px;">
                      <strong>${idx + 1}. ${email.template_type || 'Email'}</strong>
                    </p>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #666;">
                      ${new Date(email.created_at).toLocaleString('en-GB')}
                    </p>
                  </div>
                  ${email.original_email_text ? `
                    <div style="margin-bottom: 15px;">
                      <p style="margin: 0 0 5px 0; font-size: 13px; font-weight: 600; color: #0284C7;">Parent's Email:</p>
                      <div style="background: #F0F9FF; padding: 10px; border-left: 3px solid #0284C7; font-size: 13px; white-space: pre-wrap; line-height: 1.5;">${email.original_email_text}</div>
                    </div>
                  ` : ''}
                  ${email.generated_email ? `
                    <div>
                      <p style="margin: 0 0 5px 0; font-size: 13px; font-weight: 600; color: #10B981;">Our Response:</p>
                      <div style="background: #F0FFF4; padding: 10px; border-left: 3px solid #10B981; font-size: 13px; white-space: pre-wrap; line-height: 1.5;">${email.generated_email}</div>
                    </div>
                  ` : ''}
                </div>
              `).join('')}
            </div>
            ` : ''}

            ${sessions.length > 0 || moduleViews.length > 0 ? `
            <div style="background: #F3E8FF; padding: 20px; border-left: 4px solid #9333EA; margin: 20px 0;">
              <h3 style="margin-top: 0; color: #9333EA;">Prospectus Viewing History</h3>
              ${sessions.length > 0 ? `
                <h4 style="margin: 15px 0 10px 0; font-size: 14px; color: #7C3AED;">Session Summaries</h4>
                ${sessions.map(session => `
                  <div style="background: white; padding: 12px; margin-bottom: 10px; border-radius: 4px; border: 1px solid #E9D5FF;">
                    <p style="margin: 0; font-size: 14px;">
                      <strong>${new Date(session.start_time).toLocaleDateString('en-GB')}</strong> •
                      ${Math.round(session.duration_seconds / 60)} mins •
                      Engagement: ${session.engagement_score}/100
                    </p>
                    <p style="margin: 8px 0 0 0; font-size: 12px; color: #666;">
                      Sections: ${session.sections_visited} • Videos: ${session.videos_played}
                    </p>
                  </div>
                `).join('')}
              ` : ''}
              ${moduleViews.length > 0 ? `
                <h4 style="margin: 15px 0 10px 0; font-size: 14px; color: #7C3AED;">Module Views</h4>
                ${moduleViews.map(view => `
                  <div style="background: white; padding: 12px; margin-bottom: 10px; border-radius: 4px; border: 1px solid #E9D5FF;">
                    <p style="margin: 0; font-size: 14px;">
                      <strong>${view.module_name}</strong>
                    </p>
                    <p style="margin: 8px 0 0 0; font-size: 12px; color: #666;">
                      ${new Date(view.started_at).toLocaleString('en-GB')} •
                      ${Math.round(view.time_spent_seconds / 60)} mins •
                      Scroll: ${view.scroll_depth_percent}%
                    </p>
                  </div>
                `).join('')}
              ` : ''}
            </div>
            ` : ''}

            ${isNew && booking.feedback_token ? `
            <div style="background: #FEF3C7; padding: 20px; border-left: 4px solid #F59E0B; margin: 20px 0; border-radius: 4px;">
              <h3 style="margin: 0 0 10px 0; color: #92400E;">📝 Submit SMART Feedback After ${booking.booking_type === 'taster_day' ? 'Taster Day' : 'Tour'}</h3>
              <p style="margin: 0 0 15px 0;">After completing the ${booking.booking_type === 'taster_day' ? 'taster day' : 'tour'}, please share your observations about the student and parent using our SMART feedback system.</p>
              <div style="text-align: center; margin-top: 15px;">
                <a href="${process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com'}/${booking.booking_type === 'taster_day' ? 'taster-feedback-form.html' : 'tour-feedback-form.html'}?token=${booking.feedback_token}"
                   style="display: inline-block; background: #FF9F1C; color: #091825; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">
                  Submit ${booking.booking_type === 'taster_day' ? 'Taster Day' : 'Tour'} Feedback
                </a>
              </div>
            </div>
            ` : ''}

            <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #666; font-size: 14px;">
              <p style="margin: 0;">This is an automated notification from the More House School booking system.</p>
              <p style="margin: 10px 0 0 0;">If you have any questions, please contact the admissions team.</p>
            </div>
          </div>
        </div>
      `;

      // Send email using the transporter
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: guide.email,
        subject: subject,
        html: body
      });

      console.log(`[REASSIGN GUIDE] Email sent to ${guide.name} (${guide.email})`);
    };

    // Send email to old guide if exists
    if (oldGuideId) {
      await sendGuideEmail(oldGuideId, false);
    }

    // Send email to new guide if exists
    if (newGuideId) {
      await sendGuideEmail(newGuideId, true);
    }

    res.json({ success: true, message: 'Guide reassignment emails sent' });
  } catch (error) {
    console.error('[REASSIGN GUIDE] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to send guide emails' });
  }
});

// Mark booking as no-show
app.put('/api/bookings/:id/no-show', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE bookings SET
        no_show_at = NOW(),
        updated_at = NOW()
      WHERE id = $1
      RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Send no-show follow-up email
    try {
      // Get the no-show email template based on booking type
      const templateRes = await pool.query(
        `SELECT * FROM email_templates
         WHERE school_id = $1
         AND template_type = 'no_show'
         AND (booking_type = $2 OR booking_type = 'both')
         AND is_active = true
         LIMIT 1`,
        [booking.school_id, booking.booking_type]
      );

      if (templateRes.rows.length > 0) {
        // Get event details if this is an open day booking
        let eventTitle = 'your scheduled visit';
        let eventDate = '';

        if (booking.event_id) {
          const eventRes = await pool.query('SELECT title, event_date FROM events WHERE id = $1', [booking.event_id]);
          if (eventRes.rows.length > 0) {
            eventTitle = eventRes.rows[0].title;
            eventDate = new Date(eventRes.rows[0].event_date).toLocaleDateString('en-GB', {
              weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
            });
          }
        } else if (booking.scheduled_date) {
          eventDate = new Date(booking.scheduled_date).toLocaleDateString('en-GB', {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
          });
        }

        const template = templateRes.rows[0];

        // Replace variables in subject and body
        const variables = {
          '{{parent_name}}': `${booking.parent_first_name} ${booking.parent_last_name}`,
          '{{parent_first_name}}': booking.parent_first_name || '',
          '{{student_name}}': `${booking.student_first_name} ${booking.student_last_name || ''}`.trim(),
          '{{student_first_name}}': booking.student_first_name || '',
          '{{child_name}}': booking.student_first_name || '',
          '{{school_name}}': 'More House School',
          '{{event_title}}': eventTitle,
          '{{event_date}}': eventDate,
          '{{scheduled_date}}': eventDate,
          '{{tour_date}}': eventDate,
          '{{booking_type}}': booking.booking_type === 'open_day' ? 'Open Day'
            : booking.booking_type === 'taster_day' ? 'Taster Day'
            : 'Private Tour',
        };

        let subject = template.subject;
        let body = template.body;

        Object.keys(variables).forEach(key => {
          subject = subject.replace(new RegExp(key, 'g'), variables[key]);
          body = body.replace(new RegExp(key, 'g'), variables[key]);
        });

        // Send the email via email worker for branded template
        await emailWorker.sendEmail({
          to: booking.email,
          subject: subject,
          text: body
        });

        console.log(`[NO-SHOW] No-show follow-up email sent to ${booking.email} for booking #${id}`);
      } else {
        console.log(`[NO-SHOW] No email template found for booking type: ${booking.booking_type}`);
      }
    } catch (emailError) {
      console.error('[NO-SHOW] Failed to send email:', emailError);
      // Don't fail the whole request if email fails
    }

    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('Mark as no-show error:', error);
    res.status(500).json({ success: false, error: 'Failed to mark as no-show' });
  }
});

// Update booking status
app.put('/api/bookings/:id/status', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, assigned_guide_id } = req.body;

    const result = await pool.query(
      `UPDATE bookings SET
        status = $1,
        assigned_guide_id = $2,
        updated_at = NOW()
      WHERE id = $3
      RETURNING *`,
      [status, assigned_guide_id || null, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Send status update email
    try {
      let emailSubject = '';
      let emailBody = '';

      if (status === 'confirmed') {
        emailSubject = 'Booking Confirmed';
        emailBody = '<p>Great news! Your booking has been confirmed.</p>';
      } else if (status === 'cancelled') {
        emailSubject = 'Booking Cancelled';
        emailBody = '<p>Your booking has been cancelled.</p>';
      }

      const emailHtml = `
          <h2>${emailSubject}</h2>
          <p>Dear ${booking.parent_first_name} ${booking.parent_last_name},</p>
          ${emailBody}
          <p>Booking Reference: #${booking.id}</p>
        `;

      // Send via email worker for branded template
      await emailWorker.sendEmail({
        to: booking.email,
        subject: emailSubject,
        html: emailHtml
      });

      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'status_update', booking.email, emailSubject]
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
    }

    res.json({ success: true, booking });
  } catch (error) {
    console.error('Update booking status error:', error);
    res.status(500).json({ success: false, error: 'Failed to update booking status' });
  }
});

// Check-in booking
app.post('/api/bookings/:id/checkin', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE bookings SET
        checked_in_at = NOW(),
        checked_in_by = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING *`,
      [req.session.userId, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Note: Follow-up emails are now sent when guide submits feedback (see feedback submission endpoint)
    // No longer sending follow-up email on check-in

    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('Check-in error:', error);
    res.status(500).json({ success: false, error: 'Failed to check in' });
  }
});

// Get email history for a booking
app.get('/api/bookings/:id/email-history', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // First get the booking to find the inquiry_id
    const bookingResult = await pool.query(
      'SELECT inquiry_id FROM bookings WHERE id = $1',
      [id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const { inquiry_id } = bookingResult.rows[0];

    if (!inquiry_id) {
      return res.json({ success: true, emails: [] });
    }

    // Get regular email history
    const emailResult = await pool.query(
      `SELECT
        id,
        enquiry_id,
        message_id,
        direction,
        from_email,
        from_name,
        to_email,
        to_name,
        subject,
        body_text,
        sent_at,
        received_at,
        admin_email
      FROM email_history
      WHERE enquiry_id = $1 AND is_deleted = false
      ORDER BY COALESCE(sent_at, received_at) ASC,
               CASE direction WHEN 'received' THEN 0 WHEN 'sent' THEN 1 END ASC,
               id ASC`,
      [inquiry_id]
    );

    // Also get AI-generated email history from smart CRM
    const aiEmailResult = await pool.query(
      `SELECT
        id,
        inquiry_id as enquiry_id,
        parent_email as from_email,
        parent_name as from_name,
        '' as to_email,
        '' as to_name,
        '' as subject,
        original_email_text as original_text,
        generated_email as body_text,
        created_at as sent_at,
        sentiment_score,
        sentiment_label,
        sentiment_reasoning,
        'ai-generated' as direction
      FROM email_generation_history
      WHERE inquiry_id = $1
      ORDER BY created_at ASC`,
      [inquiry_id]
    );

    // Combine both results
    const allEmails = [...emailResult.rows, ...aiEmailResult.rows].sort((a, b) => {
      const timeA = new Date(a.sent_at || a.received_at);
      const timeB = new Date(b.sent_at || b.received_at);
      return timeA - timeB;
    });

    res.json({ success: true, emails: allEmails });
  } catch (error) {
    console.error('Get email history error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch email history' });
  }
});

// Get booking notes
app.get('/api/bookings/:id/notes', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // First get the booking to find the inquiry_id
    const bookingResult = await pool.query(
      'SELECT inquiry_id FROM bookings WHERE id = $1',
      [id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const { inquiry_id } = bookingResult.rows[0];

    if (!inquiry_id) {
      return res.json({ success: true, notes: [] });
    }

    // Get notes for this inquiry from inquiry_notes table (same as CRM)
    const result = await pool.query(
      `SELECT
        n.id,
        n.note_text as content,
        n.created_at,
        n.updated_at,
        n.created_by,
        n.updated_by,
        CONCAT(creator.first_name, ' ', creator.last_name) as admin_email,
        creator.email as created_by_email
      FROM inquiry_notes n
      LEFT JOIN admin_users creator ON n.created_by = creator.id
      LEFT JOIN admin_users updater ON n.updated_by = updater.id
      WHERE n.inquiry_id = $1
      ORDER BY n.created_at DESC`,
      [inquiry_id]
    );

    res.json({ success: true, notes: result.rows });
  } catch (error) {
    console.error('Get booking notes error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch booking notes' });
  }
});

// Create a booking note
app.post('/api/bookings/:id/notes', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { note } = req.body;
    const adminEmail = req.session?.adminEmail || 'system'; // Use admin email instead of user ID

    if (!note || !note.trim()) {
      return res.status(400).json({ success: false, error: 'Note content is required' });
    }

    // First get the booking to find the inquiry_id
    const bookingResult = await pool.query(
      'SELECT inquiry_id FROM bookings WHERE id = $1',
      [id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const { inquiry_id } = bookingResult.rows[0];

    if (!inquiry_id) {
      return res.status(400).json({ success: false, error: 'Booking has no associated inquiry' });
    }

    // Get user ID from session
    const userId = req.session?.userId || 1; // Fallback to admin user ID 1

    // Insert into inquiry_notes table (same as CRM)
    const result = await pool.query(
      `INSERT INTO inquiry_notes (inquiry_id, note_text, created_by)
       VALUES ($1, $2, $3)
       RETURNING id, note_text as content, created_at`,
      [inquiry_id, note.trim(), userId]
    );

    // Add activity log entry
    try {
      await pool.query(
        `INSERT INTO enquiry_activities (enquiry_id, activity_type, description, admin_email, created_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [
          inquiry_id,
          'note_added',
          `Note added: ${note.trim().substring(0, 100)}${note.trim().length > 100 ? '...' : ''}`,
          adminEmail
        ]
      );
      console.log(`[BOOKING APP] Added activity log entry for note on enquiry ${inquiry_id}`);
    } catch (activityError) {
      console.error('[BOOKING APP] Failed to log activity:', activityError.message);
    }

    res.json({ success: true, note: result.rows[0] });
  } catch (error) {
    console.error('Create booking note error:', error);
    res.status(500).json({ success: false, error: 'Failed to create note' });
  }
});

// Get session/prospectus viewing history for a booking
app.get('/api/bookings/:id/sessions', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // First get the booking to find the inquiry_id
    const bookingResult = await pool.query(
      'SELECT inquiry_id FROM bookings WHERE id = $1',
      [id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const { inquiry_id } = bookingResult.rows[0];

    if (!inquiry_id) {
      return res.json({ success: true, visits: [] });
    }

    // Get all tracking events for this inquiry, ordered by session and time
    const eventsResult = await pool.query(`
      SELECT
        session_id,
        event_type,
        timestamp,
        country,
        event_data
      FROM tracking_events
      WHERE inquiry_id = $1
      ORDER BY session_id, timestamp ASC
    `, [inquiry_id]);

    // Group events by session_id to create visits (same as admin app)
    const sessionsMap = new Map();

    for (const event of eventsResult.rows) {
      const sessionId = event.session_id;
      if (!sessionsMap.has(sessionId)) {
        sessionsMap.set(sessionId, {
          session_id: sessionId,
          started_at: event.timestamp,
          ended_at: event.timestamp,
          country: event.country,
          sections: [],
          total_time: 0
        });
      }

      const session = sessionsMap.get(sessionId);
      session.ended_at = event.timestamp;

      // Track section views with dwell time
      if ((event.event_type === 'section_exit' || event.event_type === 'section_exit_enhanced') && event.event_data) {
        const section = event.event_data.section;
        const dwellSec = parseFloat(event.event_data.dwellSec) || 0;
        if (section) {
          session.sections.push({
            section: section,
            time_spent: dwellSec
          });
          session.total_time += dwellSec;
        }
      }
    }

    // Convert to array and sort by start time descending (most recent first)
    const visits = Array.from(sessionsMap.values())
      .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
      .map((visit, index, arr) => ({
        ...visit,
        visit_number: arr.length - index // Visit 1 is oldest, Visit N is newest
      }));

    res.json({
      success: true,
      visits: visits,
      total_visits: visits.length
    });
  } catch (error) {
    console.error('Get session history error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch session history' });
  }
});

// Assign tour guide to open day booking
app.post('/api/bookings/:id/assign-guide', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { guideId } = req.body;

    if (!guideId) {
      return res.status(400).json({ success: false, error: 'Guide ID is required' });
    }

    // Get guide details with email
    const guideResult = await pool.query('SELECT id, name, email FROM tour_guides WHERE id = $1', [guideId]);

    if (guideResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Tour guide not found' });
    }

    const guide = guideResult.rows[0];

    // Generate feedback token if it doesn't exist
    const feedbackToken = crypto.randomBytes(32).toString('hex');

    // Update the booking with the assigned guide and feedback token
    const result = await pool.query(
      `UPDATE bookings SET
        assigned_guide_id = $1,
        feedback_token = COALESCE(feedback_token, $3),
        updated_at = NOW()
      WHERE id = $2
      RETURNING *`,
      [guideId, id, feedbackToken]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    // Get booking with event details and feedback token for email
    const bookingWithEventResult = await pool.query(
      `SELECT b.*, e.title as event_title, e.event_date, e.start_time
       FROM bookings b
       LEFT JOIN events e ON b.event_id = e.id
       WHERE b.id = $1`,
      [id]
    );

    const booking = bookingWithEventResult.rows[0];

    // Send assignment notification with calendar invite
    console.log(`📧 Sending assignment notification to tour guide: ${guide.name}`);
    await sendTourGuideNotification(booking, guide, 'assignment');

    res.json({ success: true, booking: booking });
  } catch (error) {
    console.error('Assign guide error:', error);
    res.status(500).json({ success: false, error: 'Failed to assign guide' });
  }
});

// Schedule/Accept booking (Admin endpoint)
app.post('/api/bookings/:id/schedule', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { scheduled_date, scheduled_time, assigned_guide_id } = req.body;

    // Generate response token for parent interactions and feedback token for tour guide
    const responseToken = crypto.randomBytes(32).toString('hex');
    const feedbackToken = crypto.randomBytes(32).toString('hex');

    const result = await pool.query(
      `UPDATE bookings SET
        status = 'confirmed',
        scheduled_date = $1,
        scheduled_time = $2,
        assigned_guide_id = $3,
        response_token = $4,
        feedback_token = COALESCE(feedback_token, $6),
        updated_at = NOW()
      WHERE id = $5
      RETURNING *`,
      [scheduled_date, scheduled_time, assigned_guide_id, responseToken, id, feedbackToken]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    // Get booking with event details for emails
    const bookingWithEventResult = await pool.query(
      `SELECT b.*, e.title as event_title, e.event_date, e.start_time
       FROM bookings b
       LEFT JOIN events e ON b.event_id = e.id
       WHERE b.id = $1`,
      [id]
    );

    const booking = bookingWithEventResult.rows[0];

    // Get tour guide details if assigned
    let guide = null;
    if (assigned_guide_id) {
      const guideResult = await pool.query(
        'SELECT * FROM tour_guides WHERE id = $1',
        [assigned_guide_id]
      );
      guide = guideResult.rows[0];
    }

    // Send confirmation email
    try {
      const scheduledDateTime = `${new Date(scheduled_date).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at ${scheduled_time}`;

      const emailSubject = `More House School - Tour Confirmed for ${scheduledDateTime}`;
      const emailText = `Dear ${booking.parent_first_name} ${booking.parent_last_name},

Great news! Your private tour request has been scheduled.

Tour Details:
- Date & Time: ${scheduledDateTime}
- Location: More House School
- Number of Attendees: ${booking.num_attendees}
${booking.student_first_name ? `- Student: ${booking.student_first_name} ${booking.student_last_name}\n` : ''}
${guide ? `- Your Tour Guide: ${guide.name}\n` : ''}

We look forward to welcoming you to More House School!

If you need to reschedule or have any questions, please contact the admissions team.

Best regards,
More House School Admissions Team`;

      const emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Tour Confirmed!</h2>
            <p>Dear ${booking.parent_first_name} ${booking.parent_last_name},</p>
            <p>Great news! Your private tour request has been <strong>confirmed and scheduled</strong>.</p>

            <h3 style="color: #091825;">Tour Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Date & Time:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${scheduledDateTime}</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Location:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">More House School</td></tr>
              <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Attendees:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${booking.num_attendees}</td></tr>
              ${booking.student_first_name ? `<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Student:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${booking.student_first_name} ${booking.student_last_name}</td></tr>` : ''}
              ${guide ? `<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Tour Guide:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${guide.name}</td></tr>` : ''}
            </table>

            <p style="margin-top: 20px;">We look forward to welcoming you to More House School!</p>
            <p style="margin-top: 10px;">If you need to reschedule or have any questions, please contact the admissions team.</p>
          </div>
        `;

      // Send via email worker for branded template
      await emailWorker.sendEmail({
        to: booking.email,
        subject: emailSubject,
        text: emailText,
        html: emailHtml
      });

      // Log email
      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'tour_scheduled', booking.email, emailSubject]
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
    }

    // Send notification to tour guide if assigned
    if (guide) {
      console.log(`📧 Sending assignment notification to tour guide: ${guide.name}`);
      await sendTourGuideNotification(booking, guide, 'assignment');
    }

    res.json({ success: true, booking, guide });
  } catch (error) {
    console.error('Schedule booking error:', error);
    res.status(500).json({ success: false, error: 'Failed to schedule booking' });
  }
});

// Decline booking with alternatives (Admin endpoint)
app.post('/api/bookings/:id/decline', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { decline_reason, alternative_dates } = req.body;

    // Generate response token for parent interactions
    const responseToken = crypto.randomBytes(32).toString('hex');

    const result = await pool.query(
      `UPDATE bookings SET
        status = 'declined',
        decline_reason = $1,
        alternative_dates = $2,
        response_token = $3,
        updated_at = NOW()
      WHERE id = $4
      RETURNING *`,
      [decline_reason, JSON.stringify(alternative_dates || []), responseToken, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Send decline email with alternatives
    try {
      const hasAlternatives = alternative_dates && alternative_dates.length > 0;

      let alternativesText = '';
      let alternativesHTML = '';

      const appUrl = process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com';

      // Always include request a call option
      const requestCallText = `\n\nWould you prefer us to call you? Request a callback:\n${appUrl}/respond.html?token=${responseToken}&action=call`;
      const requestCallHTML = `
        <p style="margin-top: 20px;">
          <a href="${appUrl}/respond.html?token=${responseToken}&action=call"
             style="display: inline-block; padding: 12px 24px; background: #091825; color: white; text-decoration: none; border-radius: 4px; font-weight: 600;">
            Request a Call from Admissions
          </a>
        </p>
      `;

      if (hasAlternatives) {
        alternativesText = '\n\nAlternative dates available:\n' +
          alternative_dates.map((alt, idx) => `${idx + 1}. ${alt.date} at ${alt.time}`).join('\n') +
          `\n\nTo accept one of these alternatives, please visit:\n${appUrl}/respond.html?token=${responseToken}` +
          requestCallText;

        alternativesHTML = `
          <h3 style="color: #091825; margin-top: 20px;">Alternative Dates Available</h3>
          <ul style="list-style: none; padding: 0;">
            ${alternative_dates.map(alt => `
              <li style="padding: 10px; margin: 5px 0; background: #f8f9fa; border-left: 3px solid var(--award-gold);">
                <strong>${alt.date}</strong> at ${alt.time}
              </li>
            `).join('')}
          </ul>
          <p style="margin-top: 20px;">
            <a href="${appUrl}/respond.html?token=${responseToken}"
               style="display: inline-block; padding: 12px 24px; background: #FF9F1C; color: white; text-decoration: none; border-radius: 4px; font-weight: 600;">
              View & Accept Alternative Dates
            </a>
          </p>
          <p style="margin-top: 10px; color: #666;">Or if you'd prefer to discuss options:</p>
          ${requestCallHTML}
        `;
      } else {
        alternativesText = requestCallText;
        alternativesHTML = requestCallHTML;
      }

      const emailSubject = `More House School - Tour Request Update`;
      const emailText = `Dear ${booking.parent_first_name} ${booking.parent_last_name},

Thank you for your interest in More House School.

Unfortunately, your requested date is not available.

${decline_reason ? `Reason: ${decline_reason}\n` : ''}${alternativesText}

${!hasAlternatives ? 'Please contact us to discuss alternative arrangements or submit a new tour request.' : ''}

Best regards,
More House School Admissions Team`;

      const emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Tour Request Update</h2>
            <p>Dear ${booking.parent_first_name} ${booking.parent_last_name},</p>
            <p>Thank you for your interest in More House School.</p>
            <p>Unfortunately, your requested date is not available.</p>

            ${decline_reason ? `<p style="padding: 10px; background: #f8f9fa; border-left: 3px solid #6c757d;"><strong>Reason:</strong> ${decline_reason}</p>` : ''}

            ${alternativesHTML}

            ${!hasAlternatives ? `<p style="margin-top: 20px;">Please contact us to discuss alternative arrangements or submit a new tour request.</p>${requestCallHTML}` : ''}
          </div>
        `;

      // Send via email worker for branded template
      await emailWorker.sendEmail({
        to: booking.email,
        subject: emailSubject,
        text: emailText,
        html: emailHtml
      });

      // Log email
      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'tour_declined', booking.email, emailSubject]
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
    }

    res.json({ success: true, booking });
  } catch (error) {
    console.error('Decline booking error:', error);
    res.status(500).json({ success: false, error: 'Failed to decline booking' });
  }
});

// Parent accepts alternative date (Public endpoint)
app.post('/api/bookings/accept-alternative', requireAdminAuth, async (req, res) => {
  try {
    const { token, selected_date, selected_time } = req.body;

    const result = await pool.query(
      `UPDATE bookings SET
        status = 'confirmed',
        scheduled_date = $1,
        scheduled_time = $2,
        decline_reason = NULL,
        alternative_dates = NULL,
        updated_at = NOW()
      WHERE response_token = $3 AND status = 'declined'
      RETURNING *`,
      [selected_date, selected_time, token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found or already processed' });
    }

    const booking = result.rows[0];

    // Send confirmation email
    try {
      const scheduledDateTime = `${new Date(selected_date).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at ${selected_time}`;

      const emailSubject = `More House School - Tour Confirmed for ${scheduledDateTime}`;
      const emailText = `Dear ${booking.parent_first_name} ${booking.parent_last_name},

Thank you for selecting an alternative date!

Your tour has been confirmed for:
${scheduledDateTime}

We look forward to welcoming you to More House School!

Best regards,
More House School Admissions Team`;

      const emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #091825;">Tour Confirmed!</h2>
            <p>Dear ${booking.parent_first_name} ${booking.parent_last_name},</p>
            <p>Thank you for selecting an alternative date!</p>
            <p>Your tour has been <strong>confirmed</strong> for:</p>
            <p style="font-size: 18px; color: #091825; font-weight: 600;">${scheduledDateTime}</p>
            <p style="margin-top: 20px;">We look forward to welcoming you to More House School!</p>
          </div>
        `;

      // Send via email worker for branded template
      await emailWorker.sendEmail({
        to: booking.email,
        subject: emailSubject,
        text: emailText,
        html: emailHtml
      });

      // Log email
      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'alternative_accepted', booking.email, emailSubject]
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
    }

    res.json({ success: true, booking });
  } catch (error) {
    console.error('Accept alternative error:', error);
    res.status(500).json({ success: false, error: 'Failed to accept alternative' });
  }
});

// Request a call from admissions (Public endpoint)
app.post('/api/bookings/request-call', async (req, res) => {
  try {
    const { token } = req.body;

    const result = await pool.query(
      'SELECT * FROM bookings WHERE response_token = $1',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = result.rows[0];

    // Update booking to mark call requested
    await pool.query(
      `UPDATE bookings SET
        call_requested = true,
        call_requested_at = NOW(),
        updated_at = NOW()
      WHERE id = $1`,
      [booking.id]
    );

    // Create follow-up reminder in CRM if booking has inquiry_id
    if (booking.inquiry_id) {
      try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        await pool.query(
          `INSERT INTO follow_ups (inquiry_id, follow_up_type, due_date, notes, status, priority, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
          [
            booking.inquiry_id,
            'call',
            today, // Due today - ASAP
            `URGENT: Parent requested a callback regarding declined tour booking. Phone: ${booking.phone || 'Check enquiry'}. Original request: ${booking.booking_type === 'private_tour' ? 'Private Tour' : booking.booking_type === 'taster_day' ? 'Taster Day' : 'Open Day'}`,
            'pending',
            'high'
          ]
        );
        console.log(`[REQUEST CALL] Created follow-up reminder for inquiry ${booking.inquiry_id}`);
      } catch (followUpError) {
        console.error('[REQUEST CALL] Failed to create follow-up:', followUpError.message);
      }
    }

    // Send notification email to admissions (via email worker for branded template)
    try {
      const adminSubject = `Call Request - ${booking.parent_first_name} ${booking.parent_last_name}`;
      const adminText = `A parent has requested a call from admissions regarding their tour booking.

Parent: ${booking.parent_first_name} ${booking.parent_last_name}
Email: ${booking.email}
Phone: ${booking.phone || 'Not provided'}
Student: ${booking.student_first_name} ${booking.student_last_name}

Original booking type: ${booking.booking_type === 'private_tour' ? 'Private Tour' : booking.booking_type === 'taster_day' ? 'Taster Day' : 'Open Day'}
Original requested date: ${booking.scheduled_date || 'Not specified'}

This booking was declined and the parent would like to discuss alternative arrangements.

Please call them at your earliest convenience.`;

      await emailWorker.sendEmail({
        to: process.env.ADMIN_EMAIL,
        subject: adminSubject,
        text: adminText
      });

      // Log the email
      await pool.query(
        `INSERT INTO booking_email_logs (booking_id, email_type, recipient, subject, sent_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [booking.id, 'call_requested', process.env.ADMIN_EMAIL, adminSubject]
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
    }

    // Send confirmation to parent (via email worker for branded template)
    try {
      const parentSubject = `More House School - Call Request Received`;
      const parentText = `Dear ${booking.parent_first_name},

Thank you for your interest in More House School.

We have received your request for a call from our admissions team. A member of our team will contact you shortly.

If you need to reach us urgently, please call us directly on 020 7235 2855.

Best regards,
More House School Admissions Team`;

      await emailWorker.sendEmail({
        to: booking.email,
        subject: parentSubject,
        text: parentText
      });
    } catch (emailError) {
      console.error('Confirmation email error:', emailError);
    }

    res.json({ success: true, message: 'Call request submitted' });
  } catch (error) {
    console.error('Request call error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit call request' });
  }
});

// Get booking by response token (Public endpoint)
app.get('/api/bookings/by-token/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
      'SELECT * FROM bookings WHERE response_token = $1',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('Get booking by token error:', error);
    res.status(500).json({ success: false, error: 'Failed to get booking' });
  }
});

// Cancel booking via token (Public endpoint)
app.post('/api/bookings/cancel', async (req, res) => {
  try {
    const { token, cancellationToken, reason } = req.body;
    const actualToken = token || cancellationToken;

    const result = await pool.query(
      `UPDATE bookings SET
        status = 'cancelled',
        cancelled_at = NOW(),
        cancellation_reason = $1,
        updated_at = NOW()
      WHERE cancellation_token = $2 AND status != 'cancelled'
      RETURNING *`,
      [reason || 'Cancelled by user', actualToken]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found or already cancelled' });
    }

    const booking = result.rows[0];

    // Update event booking count
    await pool.query(
      'UPDATE events SET current_bookings = current_bookings - $1 WHERE id = $2',
      [booking.num_attendees, booking.event_id]
    );

    res.json({ success: true, message: 'Booking cancelled successfully' });
  } catch (error) {
    console.error('Cancel booking error:', error);
    res.status(500).json({ success: false, error: 'Failed to cancel booking' });
  }
});

// ==================== TOUR GUIDES ENDPOINTS ====================

// Get all tour guides for a school
app.get('/api/tour-guides', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId } = req.query;
    const school_id = schoolId || 2; // Default to school 2

    const result = await pool.query(
      'SELECT * FROM tour_guides WHERE school_id = $1 ORDER BY name ASC',
      [school_id]
    );

    res.json({ success: true, guides: result.rows });
  } catch (error) {
    console.error('Get tour guides error:', error);
    res.status(500).json({ success: false, error: 'Failed to get tour guides' });
  }
});

// Create tour guide
app.post('/api/tour-guides', requireAdminAuth, async (req, res) => {
  try {
    const { school_id, name, email, phone, type } = req.body;

    const result = await pool.query(
      `INSERT INTO tour_guides (school_id, name, email, phone, type)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [school_id, name, email, phone, type]
    );

    res.json({ success: true, guide: result.rows[0] });
  } catch (error) {
    console.error('Create tour guide error:', error);
    res.status(500).json({ success: false, error: 'Failed to create tour guide' });
  }
});

// Update tour guide
app.put('/api/tour-guides/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, type, is_active } = req.body;

    const result = await pool.query(
      `UPDATE tour_guides SET
        name = $1,
        email = $2,
        phone = $3,
        type = $4,
        is_active = $5
      WHERE id = $6
      RETURNING *`,
      [name, email, phone, type, is_active, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Tour guide not found' });
    }

    res.json({ success: true, guide: result.rows[0] });
  } catch (error) {
    console.error('Update tour guide error:', error);
    res.status(500).json({ success: false, error: 'Failed to update tour guide' });
  }
});

// Delete tour guide
app.delete('/api/tour-guides/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM tour_guides WHERE id = $1', [id]);
    res.json({ success: true, message: 'Tour guide deleted successfully' });
  } catch (error) {
    console.error('Delete tour guide error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete tour guide' });
  }
});

// ==================== EMAIL TEMPLATES ENDPOINTS ====================

// Get all email templates for a school
app.get('/api/email-templates', requireAdminAuth, async (req, res) => {
  try {
    const schoolId = req.query.schoolId || 2;
    const result = await pool.query(
      'SELECT * FROM email_templates WHERE school_id = $1 ORDER BY created_at DESC',
      [schoolId]
    );
    res.json({ success: true, templates: result.rows });
  } catch (error) {
    console.error('Get email templates error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch email templates' });
  }
});

// Create new email template
app.post('/api/email-templates', requireAdminAuth, async (req, res) => {
  try {
    const {
      schoolId = 2,
      name,
      bookingType = 'both',
      templateType,
      subject,
      body,
      isActive = true,
      enableAutomation = false,
      automationTrigger = null,
      automationDays = null,
      automationTiming = null
    } = req.body;

    const result = await pool.query(
      `INSERT INTO email_templates
       (school_id, name, booking_type, template_type, subject, body, is_active, enable_automation,
        automation_trigger, automation_days, automation_timing)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING *`,
      [schoolId, name, bookingType, templateType, subject, body, isActive, enableAutomation,
       automationTrigger, automationDays, automationTiming]
    );

    res.json({ success: true, template: result.rows[0] });
  } catch (error) {
    console.error('Create email template error:', error);
    res.status(500).json({ success: false, error: 'Failed to create email template' });
  }
});

// Update email template
app.put('/api/email-templates/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      bookingType,
      templateType,
      subject,
      body,
      isActive,
      enableAutomation,
      automationTrigger,
      automationDays,
      automationTiming
    } = req.body;

    const result = await pool.query(
      `UPDATE email_templates
       SET name = $1, booking_type = $2, template_type = $3, subject = $4, body = $5, is_active = $6,
           enable_automation = $7, automation_trigger = $8, automation_days = $9,
           automation_timing = $10, updated_at = CURRENT_TIMESTAMP
       WHERE id = $11
       RETURNING *`,
      [name, bookingType, templateType, subject, body, isActive, enableAutomation,
       automationTrigger, automationDays, automationTiming, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }

    res.json({ success: true, template: result.rows[0] });
  } catch (error) {
    console.error('Update email template error:', error);
    res.status(500).json({ success: false, error: 'Failed to update email template' });
  }
});

// Delete email template
app.delete('/api/email-templates/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM email_templates WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }

    res.json({ success: true, message: 'Email template deleted successfully' });
  } catch (error) {
    console.error('Delete email template error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete email template' });
  }
});

// ==================== FORM TEMPLATE ENDPOINTS ====================

// Get settings (includes prospectus integration info)
app.get('/api/settings', async (req, res) => {
  try {
    // Default to school_id = 2 (More House School)
    const schoolId = 2;

    const result = await pool.query(
      'SELECT * FROM booking_settings WHERE school_id = $1',
      [schoolId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Settings not found' });
    }

    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to get settings' });
  }
});

// Upload school logo - stores as base64 in database
app.post('/api/settings/upload-logo', logoUpload.single('logo'), requireAdminAuth, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    const schoolId = 2; // Default to More House School

    // Convert file to base64 data URI
    const base64Data = req.file.buffer ?
      req.file.buffer.toString('base64') :
      fs.readFileSync(req.file.path).toString('base64');
    const mimeType = req.file.mimetype;
    const dataUri = `data:${mimeType};base64,${base64Data}`;

    // Clean up temp file if it exists
    if (req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    // Store base64 in database
    await pool.query(
      'UPDATE booking_settings SET logo_data = $1, logo_url = $2 WHERE school_id = $3',
      [dataUri, 'database', schoolId]
    );

    res.json({
      success: true,
      logo_url: dataUri,
      message: 'Logo uploaded successfully'
    });
  } catch (error) {
    console.error('Upload logo error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload logo' });
  }
});

// Get active form template for a school
app.get('/api/form-template', async (req, res) => {
  try {
    // Default to school_id = 2 (More House School)
    const schoolId = 2;

    // Get active template
    const templateResult = await pool.query(
      'SELECT * FROM enquiry_form_templates WHERE school_id = $1 AND is_active = true LIMIT 1',
      [schoolId]
    );

    if (templateResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'No active form template found' });
    }

    const template = templateResult.rows[0];

    // Get form fields for this template
    const fieldsResult = await pool.query(
      'SELECT * FROM enquiry_form_fields WHERE template_id = $1 ORDER BY display_order',
      [template.id]
    );

    res.json({
      success: true,
      template: {
        ...template,
        fields: fieldsResult.rows
      }
    });
  } catch (error) {
    console.error('Get form template error:', error);
    res.status(500).json({ success: false, error: 'Failed to get form template' });
  }
});

// Submit enquiry form
app.post('/api/form-submit', async (req, res) => {
  try {
    const formData = req.body;

    // Get school_id from booking_settings (form builder schools only)
    const settingsResult = await pool.query(
      'SELECT school_id FROM booking_settings WHERE school_id NOT IN (SELECT school_id FROM inquiries WHERE school_id IS NOT NULL) OR school_id = (SELECT MAX(school_id) FROM booking_settings) LIMIT 1'
    );

    let schoolId;
    if (settingsResult.rows.length > 0) {
      schoolId = settingsResult.rows[0].school_id;
    } else {
      // Create new school_id
      const maxIdResult = await pool.query('SELECT COALESCE(MAX(school_id), 0) + 1 AS new_id FROM booking_settings');
      schoolId = maxIdResult.rows[0].new_id;
    }

    // Generate unique inquiry ID
    const inquiryId = `INQ-${Date.now()}${Math.floor(Math.random() * 10000)}`;

    // Insert basic info into inquiries table
    const result = await pool.query(
      `INSERT INTO inquiries (
        inquiry_id, school_id, parent_name, parent_email, contact_number,
        first_name, family_surname, age_group, entry_year
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING inquiry_id`,
      [
        inquiryId,
        schoolId,
        formData.parent_name || null,
        formData.parent_email || null,
        formData.contact_number || null,
        formData.first_name || null,
        formData.family_surname || null,
        formData.age_group || null,
        formData.entry_year || null
      ]
    );

    res.json({
      success: true,
      inquiry_id: result.rows[0].inquiry_id,
      message: 'Enquiry submitted successfully'
    });
  } catch (error) {
    console.error('Form submit error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit enquiry form' });
  }
});

// ==================== FORM TEMPLATE MANAGEMENT ENDPOINTS ====================

// Get form template with fields for editing
app.get('/api/form-template/manage', requireAdminAuth, async (req, res) => {
  try {
    const schoolId = 2; // More House School

    // Get active template
    const templateResult = await pool.query(
      'SELECT * FROM enquiry_form_templates WHERE school_id = $1 AND is_active = true LIMIT 1',
      [schoolId]
    );

    if (templateResult.rows.length === 0) {
      return res.json({ success: true, template: null, fields: [] });
    }

    const template = templateResult.rows[0];

    // Get form fields for this template
    const fieldsResult = await pool.query(
      'SELECT * FROM enquiry_form_fields WHERE template_id = $1 ORDER BY display_order',
      [template.id]
    );

    res.json({
      success: true,
      template: template,
      fields: fieldsResult.rows
    });
  } catch (error) {
    console.error('Get form template for management error:', error);
    res.status(500).json({ success: false, error: 'Failed to get form template' });
  }
});

// Update form template
app.put('/api/form-template/:templateId', requireAdminAuth, async (req, res) => {
  try {
    const { templateId } = req.params;
    const { name, description } = req.body;

    const result = await pool.query(
      `UPDATE enquiry_form_templates
       SET name = $1, description = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING *`,
      [name, description, templateId]
    );

    res.json({ success: true, template: result.rows[0] });
  } catch (error) {
    console.error('Update form template error:', error);
    res.status(500).json({ success: false, error: 'Failed to update form template' });
  }
});

// Create new form field
app.post('/api/form-field', requireAdminAuth, async (req, res) => {
  try {
    const {
      template_id,
      field_label,
      field_type,
      field_options,
      is_required,
      placeholder,
      help_text,
      display_order,
      maps_to_inquiry_column,
      show_for_gender,
      section_id
    } = req.body;

    // Auto-generate field_name based on the highest existing field number
    const maxFieldResult = await pool.query(
      `SELECT field_name FROM enquiry_form_fields
       WHERE template_id = $1 AND field_name LIKE 'field_%'
       ORDER BY CAST(SUBSTRING(field_name FROM 7) AS INTEGER) DESC
       LIMIT 1`,
      [template_id]
    );

    let nextFieldNumber = 1;
    if (maxFieldResult.rows.length > 0) {
      const maxFieldName = maxFieldResult.rows[0].field_name;
      const currentNumber = parseInt(maxFieldName.replace('field_', ''));
      nextFieldNumber = currentNumber + 1;
    } else {
      // Check if there are any fields at all (including legacy ones)
      const countResult = await pool.query(
        'SELECT COUNT(*) as count FROM enquiry_form_fields WHERE template_id = $1',
        [template_id]
      );
      nextFieldNumber = parseInt(countResult.rows[0].count) + 1;
    }

    const field_name = `field_${nextFieldNumber}`;

    // Push down all fields at or after the new display_order
    await pool.query(
      `UPDATE enquiry_form_fields
       SET display_order = display_order + 1
       WHERE template_id = $1 AND display_order >= $2`,
      [template_id, display_order]
    );

    const result = await pool.query(
      `INSERT INTO enquiry_form_fields (
        template_id, field_name, field_label, field_type, field_options,
        is_required, placeholder, help_text, display_order, maps_to_inquiry_column, show_for_gender, section_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
      [
        template_id, field_name, field_label, field_type, field_options,
        is_required, placeholder, help_text, display_order, maps_to_inquiry_column, show_for_gender || 'both', section_id || null
      ]
    );

    res.json({ success: true, field: result.rows[0] });
  } catch (error) {
    console.error('Create form field error:', error);
    res.status(500).json({ success: false, error: 'Failed to create form field' });
  }
});

// Update form field
app.put('/api/form-field/:fieldId', requireAdminAuth, async (req, res) => {
  try {
    const { fieldId } = req.params;
    const {
      field_label,
      field_type,
      field_options,
      is_required,
      placeholder,
      help_text,
      display_order,
      maps_to_inquiry_column,
      show_for_gender,
      section_id
    } = req.body;

    // Get the current field's display_order and template_id
    const currentFieldResult = await pool.query(
      'SELECT display_order, template_id FROM enquiry_form_fields WHERE id = $1',
      [fieldId]
    );

    if (currentFieldResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Field not found' });
    }

    const oldDisplayOrder = currentFieldResult.rows[0].display_order;
    const template_id = currentFieldResult.rows[0].template_id;
    const newDisplayOrder = display_order;

    // If display order is changing, adjust other fields
    if (oldDisplayOrder !== newDisplayOrder) {
      if (newDisplayOrder < oldDisplayOrder) {
        // Moving up: push down fields between new and old position
        await pool.query(
          `UPDATE enquiry_form_fields
           SET display_order = display_order + 1
           WHERE template_id = $1 AND display_order >= $2 AND display_order < $3 AND id != $4`,
          [template_id, newDisplayOrder, oldDisplayOrder, fieldId]
        );
      } else {
        // Moving down: pull up fields between old and new position
        await pool.query(
          `UPDATE enquiry_form_fields
           SET display_order = display_order - 1
           WHERE template_id = $1 AND display_order > $2 AND display_order <= $3 AND id != $4`,
          [template_id, oldDisplayOrder, newDisplayOrder, fieldId]
        );
      }
    }

    // field_name is NOT updated - it stays the same
    const result = await pool.query(
      `UPDATE enquiry_form_fields
       SET field_label = $1, field_type = $2, field_options = $3,
           is_required = $4, placeholder = $5, help_text = $6, display_order = $7,
           maps_to_inquiry_column = $8, show_for_gender = $9, section_id = $10
       WHERE id = $11
       RETURNING *`,
      [
        field_label, field_type, field_options, is_required,
        placeholder, help_text, display_order, maps_to_inquiry_column,
        show_for_gender || 'both', section_id || null, fieldId
      ]
    );

    res.json({ success: true, field: result.rows[0] });
  } catch (error) {
    console.error('Update form field error:', error);
    res.status(500).json({ success: false, error: 'Failed to update form field' });
  }
});

// Delete form field
app.delete('/api/form-field/:fieldId', requireAdminAuth, async (req, res) => {
  try {
    const { fieldId } = req.params;

    // Get the field's display_order and template_id before deleting
    const fieldResult = await pool.query(
      'SELECT display_order, template_id FROM enquiry_form_fields WHERE id = $1',
      [fieldId]
    );

    if (fieldResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Field not found' });
    }

    const deletedDisplayOrder = fieldResult.rows[0].display_order;
    const template_id = fieldResult.rows[0].template_id;

    // Delete the field
    await pool.query('DELETE FROM enquiry_form_fields WHERE id = $1', [fieldId]);

    // Pull up all fields after the deleted field
    await pool.query(
      `UPDATE enquiry_form_fields
       SET display_order = display_order - 1
       WHERE template_id = $1 AND display_order > $2`,
      [template_id, deletedDisplayOrder]
    );

    res.json({ success: true, message: 'Form field deleted successfully' });
  } catch (error) {
    console.error('Delete form field error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete form field' });
  }
});

// ==================== FORM SECTIONS ENDPOINTS ====================

// Get all sections for a template
app.get('/api/form-sections/:templateId', requireAdminAuth, async (req, res) => {
  try {
    const { templateId } = req.params;
    const result = await pool.query(
      'SELECT * FROM enquiry_form_sections WHERE template_id = $1 ORDER BY display_order ASC',
      [templateId]
    );
    res.json({ success: true, sections: result.rows });
  } catch (error) {
    console.error('Get form sections error:', error);
    res.status(500).json({ success: false, error: 'Failed to get form sections' });
  }
});

// Create new section
app.post('/api/form-section', requireAdminAuth, async (req, res) => {
  try {
    const { template_id, section_name, section_label, display_order } = req.body;

    const result = await pool.query(
      `INSERT INTO enquiry_form_sections (
        template_id, section_name, section_label, display_order
      ) VALUES ($1, $2, $3, $4)
      RETURNING *`,
      [template_id, section_name, section_label, display_order || 0]
    );

    res.json({ success: true, section: result.rows[0] });
  } catch (error) {
    console.error('Create form section error:', error);
    res.status(500).json({ success: false, error: 'Failed to create form section' });
  }
});

// Update section
app.put('/api/form-section/:sectionId', requireAdminAuth, async (req, res) => {
  try {
    const { sectionId } = req.params;
    const { section_label, display_order } = req.body;

    const result = await pool.query(
      `UPDATE enquiry_form_sections
       SET section_label = $1, display_order = $2
       WHERE id = $3
       RETURNING *`,
      [section_label, display_order, sectionId]
    );

    res.json({ success: true, section: result.rows[0] });
  } catch (error) {
    console.error('Update form section error:', error);
    res.status(500).json({ success: false, error: 'Failed to update form section' });
  }
});

// Delete section
app.delete('/api/form-section/:sectionId', requireAdminAuth, async (req, res) => {
  try {
    const { sectionId } = req.params;

    // Set fields in this section to have no section (section_id = NULL)
    await pool.query('UPDATE enquiry_form_fields SET section_id = NULL WHERE section_id = $1', [sectionId]);

    // Delete the section
    await pool.query('DELETE FROM enquiry_form_sections WHERE id = $1', [sectionId]);

    res.json({ success: true, message: 'Form section deleted successfully' });
  } catch (error) {
    console.error('Delete form section error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete form section' });
  }
});

// ==================== AUTHENTICATION ENDPOINTS ====================

// Check auth status
app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, userId: req.session.userId });
  } else {
    res.json({ authenticated: false });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// ==================== FEEDBACK & OUTCOMES ENDPOINTS ====================

// Get active feedback questions
app.get('/api/feedback/questions', async (req, res) => {
  try {
    const { booking_id, token } = req.query;
    let formId = null;

    // If booking_id or token provided, get the assigned form for that booking
    if (booking_id || token) {
      const bookingQuery = token
        ? 'SELECT b.*, e.assigned_feedback_form_id FROM bookings b LEFT JOIN events e ON e.id = b.event_id WHERE b.feedback_token = $1'
        : 'SELECT b.*, e.assigned_feedback_form_id FROM bookings b LEFT JOIN events e ON e.id = b.event_id WHERE b.id = $1';

      const bookingResult = await pool.query(bookingQuery, [token || booking_id]);

      if (bookingResult.rows.length > 0) {
        const booking = bookingResult.rows[0];

        // Use the assigned form from the event if available
        if (booking.assigned_feedback_form_id) {
          formId = booking.assigned_feedback_form_id;
        } else {
          // Fall back to default form based on booking type
          const defaultFormQuery = booking.booking_type === 'open_day'
            ? `SELECT id FROM feedback_forms WHERE school_id = 2 AND form_type = 'open_day' AND is_active = true ORDER BY id LIMIT 1`
            : `SELECT id FROM feedback_forms WHERE school_id = 2 AND form_type = 'private_tour' AND is_active = true ORDER BY id LIMIT 1`;

          const defaultFormResult = await pool.query(defaultFormQuery);
          if (defaultFormResult.rows.length > 0) {
            formId = defaultFormResult.rows[0].id;
          }
        }
      }
    }

    // Load questions from the identified form
    let query = 'SELECT * FROM feedback_questions WHERE school_id = 2 AND is_active = true';
    const params = [];

    if (formId) {
      query += ' AND form_id = $1';
      params.push(formId);
    }

    query += ' ORDER BY display_order ASC';

    const result = await pool.query(query, params);
    res.json({ success: true, questions: result.rows });
  } catch (error) {
    console.error('Get feedback questions error:', error);
    res.status(500).json({ success: false, error: 'Failed to get feedback questions' });
  }
});

// Get booking by feedback token
app.get('/api/feedback/booking/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(
      `SELECT b.*,
        EXISTS(SELECT 1 FROM feedback_responses WHERE booking_id = b.id) as feedback_submitted
       FROM bookings b
       WHERE b.feedback_token = $1`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    console.error('Get booking by feedback token error:', error);
    res.status(500).json({ success: false, error: 'Failed to get booking' });
  }
});

// Submit feedback
app.post('/api/feedback/submit', async (req, res) => {
  try {
    const { token, responses } = req.body;

    // Get booking by token
    const bookingResult = await pool.query(
      'SELECT id FROM bookings WHERE feedback_token = $1',
      [token]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const bookingId = bookingResult.rows[0].id;

    // Check if already submitted
    const existingResult = await pool.query(
      'SELECT id FROM feedback_responses WHERE booking_id = $1',
      [bookingId]
    );

    if (existingResult.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Feedback already submitted' });
    }

    // Insert responses
    for (const [questionId, response] of Object.entries(responses)) {
      await pool.query(
        `INSERT INTO feedback_responses (booking_id, question_id, response_value, rating_value)
         VALUES ($1, $2, $3, $4)`,
        [
          bookingId,
          parseInt(questionId),
          response.value?.toString(),
          response.type === 'rating' ? response.value : null
        ]
      );
    }

    console.log(`✅ Feedback submitted for booking ${bookingId}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Submit feedback error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit feedback' });
  }
});

// ==================== FEEDBACK FORMS MANAGEMENT ====================

// Get all feedback forms
app.get('/api/admin/feedback-forms', requireAdminAuth, async (req, res) => {
  try {
    const schoolId = 2;
    const result = await pool.query(
      'SELECT * FROM feedback_forms WHERE school_id = $1 ORDER BY form_type, form_name',
      [schoolId]
    );
    res.json({ success: true, forms: result.rows });
  } catch (error) {
    console.error('Get feedback forms error:', error);
    res.status(500).json({ success: false, error: 'Failed to get forms' });
  }
});

// Create feedback form
app.post('/api/admin/feedback-forms', requireAdminAuth, async (req, res) => {
  try {
    const { form_name, form_type, description } = req.body;
    const schoolId = 2;

    const result = await pool.query(
      `INSERT INTO feedback_forms (school_id, form_name, form_type, description)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [schoolId, form_name, form_type, description]
    );

    res.json({ success: true, form: result.rows[0] });
  } catch (error) {
    console.error('Create feedback form error:', error);
    res.status(500).json({ success: false, error: 'Failed to create form' });
  }
});

// Update feedback form
app.put('/api/admin/feedback-forms/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { form_name, form_type, description, is_active } = req.body;

    const result = await pool.query(
      `UPDATE feedback_forms
       SET form_name = $1, form_type = $2, description = $3, is_active = $4, updated_at = NOW()
       WHERE id = $5 RETURNING *`,
      [form_name, form_type, description, is_active, id]
    );

    res.json({ success: true, form: result.rows[0] });
  } catch (error) {
    console.error('Update feedback form error:', error);
    res.status(500).json({ success: false, error: 'Failed to update form' });
  }
});

// Delete feedback form
app.delete('/api/admin/feedback-forms/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM feedback_forms WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete feedback form error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete form' });
  }
});

// Assign feedback form to event
app.put('/api/events/:id/assign-form', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { form_id } = req.body;

    const result = await pool.query(
      `UPDATE events SET assigned_feedback_form_id = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [form_id, id]
    );

    res.json({ success: true, event: result.rows[0] });
  } catch (error) {
    console.error('Assign form to event error:', error);
    res.status(500).json({ success: false, error: 'Failed to assign form' });
  }
});

// Get all feedback questions (admin) - optionally filtered by form_id
app.get('/api/admin/feedback-questions', requireAdminAuth, async (req, res) => {
  try {
    const { form_id } = req.query;

    let query = 'SELECT * FROM feedback_questions WHERE school_id = 2';
    const params = [];

    if (form_id) {
      query += ' AND form_id = $1';
      params.push(form_id);
    }

    query += ' ORDER BY display_order ASC';

    const result = await pool.query(query, params);
    res.json({ success: true, questions: result.rows });
  } catch (error) {
    console.error('Get admin feedback questions error:', error);
    res.status(500).json({ success: false, error: 'Failed to get questions' });
  }
});

// Create feedback question
app.post('/api/admin/feedback-questions', requireAdminAuth, async (req, res) => {
  try {
    const { question_text, question_type, options, display_order, form_id } = req.body;

    const result = await pool.query(
      `INSERT INTO feedback_questions (school_id, question_text, question_type, options, display_order, form_id)
       VALUES (2, $1, $2, $3, $4, $5)
       RETURNING *`,
      [question_text, question_type, options ? JSON.stringify(options) : null, display_order || 0, form_id]
    );

    res.json({ success: true, question: result.rows[0] });
  } catch (error) {
    console.error('Create feedback question error:', error);
    res.status(500).json({ success: false, error: 'Failed to create question' });
  }
});

// Update feedback question
app.put('/api/admin/feedback-questions/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { question_text, question_type, options, is_active, display_order } = req.body;

    const result = await pool.query(
      `UPDATE feedback_questions
       SET question_text = $1, question_type = $2, options = $3, is_active = $4, display_order = $5, updated_at = NOW()
       WHERE id = $6
       RETURNING *`,
      [question_text, question_type, options ? JSON.stringify(options) : null, is_active, display_order, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Question not found' });
    }

    res.json({ success: true, question: result.rows[0] });
  } catch (error) {
    console.error('Update feedback question error:', error);
    res.status(500).json({ success: false, error: 'Failed to update question' });
  }
});

// Delete feedback question
app.delete('/api/admin/feedback-questions/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM feedback_questions WHERE id = $1', [id]);

    res.json({ success: true });
  } catch (error) {
    console.error('Delete feedback question error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete question' });
  }
});

// Get booking outcome
app.get('/api/bookings/:id/outcome', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM booking_outcomes WHERE booking_id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      res.json({ success: true, outcome: null });
    } else {
      res.json({ success: true, outcome: result.rows[0] });
    }
  } catch (error) {
    console.error('Get booking outcome error:', error);
    res.status(500).json({ success: false, error: 'Failed to get outcome' });
  }
});

// Update booking outcome
app.put('/api/bookings/:id/outcome', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { outcome_status, outcome_date, enrollment_year, notes } = req.body;

    const result = await pool.query(
      `INSERT INTO booking_outcomes (booking_id, outcome_status, outcome_date, enrollment_year, notes)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (booking_id) DO UPDATE
       SET outcome_status = $2, outcome_date = $3, enrollment_year = $4, notes = $5, updated_at = NOW()
       RETURNING *`,
      [id, outcome_status, outcome_date, enrollment_year, notes]
    );

    res.json({ success: true, outcome: result.rows[0] });
  } catch (error) {
    console.error('Update booking outcome error:', error);
    res.status(500).json({ success: false, error: 'Failed to update outcome' });
  }
});

// ==================== ANALYTICS ENDPOINTS ====================

// Get feedback statistics
app.get('/api/analytics/feedback-stats',  async (req, res) => {
  try {
    const { days = '30', type = 'all' } = req.query;
    const schoolId = 2;

    let dateCondition = '';
    if (days !== '999999') {
      dateCondition = `AND b.created_at >= NOW() - INTERVAL '${parseInt(days)} days'`;
    }

    let typeCondition = '';
    if (type !== 'all') {
      typeCondition = `AND b.booking_type = '${type}'`;
    }

    // Get overall stats
    const statsResult = await pool.query(`
      SELECT
        COUNT(DISTINCT b.id) as total_bookings,
        COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM feedback_responses WHERE booking_id = b.id) THEN b.id END) as responses_count,
        ROUND(AVG(fr.rating_value)::numeric, 2) as avg_rating,
        COUNT(DISTINCT CASE WHEN bo.outcome_status = 'enrolled' THEN b.id END) as enrolled_count
      FROM bookings b
      LEFT JOIN feedback_responses fr ON fr.booking_id = b.id
      LEFT JOIN booking_outcomes bo ON bo.booking_id = b.id
      WHERE b.school_id = $1
        AND b.status = 'confirmed'
        AND b.checked_in_at IS NOT NULL
        ${dateCondition}
        ${typeCondition}
    `, [schoolId]);

    const stats = statsResult.rows[0];
    const response_rate = stats.total_bookings > 0
      ? (stats.responses_count / stats.total_bookings) * 100
      : 0;
    const conversion_rate = stats.responses_count > 0
      ? (stats.enrolled_count / stats.responses_count) * 100
      : 0;

    res.json({
      success: true,
      stats: {
        ...stats,
        response_rate: Math.round(response_rate),
        conversion_rate: Math.round(conversion_rate)
      }
    });
  } catch (error) {
    console.error('Get feedback stats error:', error);
    res.status(500).json({ success: false, error: 'Failed to get feedback stats' });
  }
});

// Get question-by-question analytics
app.get('/api/analytics/feedback-questions',  async (req, res) => {
  try {
    const { days = '30', type = 'all' } = req.query;
    const schoolId = 2;

    let dateCondition = '';
    if (days !== '999999') {
      dateCondition = `AND b.created_at >= NOW() - INTERVAL '${parseInt(days)} days'`;
    }

    let typeCondition = '';
    if (type !== 'all') {
      typeCondition = `AND b.booking_type = '${type}'`;
    }

    // Get open day questions
    const openDayQuestionsResult = await pool.query(`
      SELECT DISTINCT fq.id, fq.question_text, fq.question_type, fq.display_order
      FROM feedback_questions fq
      JOIN feedback_forms ff ON ff.id = fq.form_id
      WHERE fq.school_id = $1 AND fq.is_active = true AND ff.form_type = 'open_day'
      ORDER BY fq.display_order ASC
    `, [schoolId]);

    // Get private tour questions
    const privateTourQuestionsResult = await pool.query(`
      SELECT DISTINCT fq.id, fq.question_text, fq.question_type, fq.display_order
      FROM feedback_questions fq
      JOIN feedback_forms ff ON ff.id = fq.form_id
      WHERE fq.school_id = $1 AND fq.is_active = true AND ff.form_type = 'private_tour'
      ORDER BY fq.display_order ASC
    `, [schoolId]);

    // Get taster day questions
    const tasterDayQuestionsResult = await pool.query(`
      SELECT DISTINCT fq.id, fq.question_text, fq.question_type, fq.display_order
      FROM feedback_questions fq
      JOIN feedback_forms ff ON ff.id = fq.form_id
      WHERE fq.school_id = $1 AND fq.is_active = true AND ff.form_type = 'taster_day'
      ORDER BY fq.display_order ASC
    `, [schoolId]);

    // Process questions with booking type filter
    const processQuestions = async (questionRows, additionalTypeCondition = '') => {
      const questions = [];
      for (const question of questionRows) {
        if (question.question_type === 'rating') {
          const ratingsResult = await pool.query(`
            SELECT
              COUNT(*) as response_count,
              ROUND(AVG(fr.rating_value)::numeric, 2) as avg_rating,
              COUNT(CASE WHEN fr.rating_value = 5 THEN 1 END) as rating_5,
              COUNT(CASE WHEN fr.rating_value = 4 THEN 1 END) as rating_4,
              COUNT(CASE WHEN fr.rating_value = 3 THEN 1 END) as rating_3,
              COUNT(CASE WHEN fr.rating_value = 2 THEN 1 END) as rating_2,
              COUNT(CASE WHEN fr.rating_value = 1 THEN 1 END) as rating_1
            FROM feedback_responses fr
            JOIN bookings b ON b.id = fr.booking_id
            WHERE fr.question_id = $1
              ${dateCondition}
              ${additionalTypeCondition}
          `, [question.id]);

          const ratings = ratingsResult.rows[0];

          questions.push({
            ...question,
            response_count: parseInt(ratings.response_count) || 0,
            avg_rating: ratings.avg_rating || 0,
            rating_breakdown: {
              5: parseInt(ratings.rating_5) || 0,
              4: parseInt(ratings.rating_4) || 0,
              3: parseInt(ratings.rating_3) || 0,
              2: parseInt(ratings.rating_2) || 0,
              1: parseInt(ratings.rating_1) || 0
            }
          });
        } else if (question.question_type === 'text') {
          const textResult = await pool.query(`
            SELECT
              fr.response_value,
              fr.submitted_at,
              b.parent_first_name || ' ' || b.parent_last_name as parent_name
            FROM feedback_responses fr
            JOIN bookings b ON b.id = fr.booking_id
            WHERE fr.question_id = $1
              AND fr.response_value IS NOT NULL
              AND fr.response_value != ''
              ${dateCondition}
              ${additionalTypeCondition}
            ORDER BY fr.submitted_at DESC
            LIMIT 50
          `, [question.id]);

          questions.push({
            ...question,
            responses: textResult.rows
          });
        }
      }
      return questions;
    };

    // Process open day questions with open_day booking type filter
    const openDayTypeCondition = `AND b.booking_type = 'open_day'`;
    const openDayQuestions = await processQuestions(openDayQuestionsResult.rows, openDayTypeCondition);

    // Process private tour questions with private_tour booking type filter
    const privateTourTypeCondition = `AND b.booking_type = 'private_tour'`;
    const privateTourQuestions = await processQuestions(privateTourQuestionsResult.rows, privateTourTypeCondition);

    // Process taster day questions with taster_day booking type filter
    const tasterDayTypeCondition = `AND b.booking_type = 'taster_day'`;
    const tasterDayQuestions = await processQuestions(tasterDayQuestionsResult.rows, tasterDayTypeCondition);

    res.json({
      success: true,
      openDayQuestions,
      privateTourQuestions,
      tasterDayQuestions
    });
  } catch (error) {
    console.error('Get feedback questions analytics error:', error);
    res.status(500).json({ success: false, error: 'Failed to get question analytics' });
  }
});

// Get conversion outcomes
app.get('/api/analytics/conversion-outcomes',  async (req, res) => {
  try {
    const { days = '30', type = 'all', outcome = 'all', entryYear = 'all' } = req.query;
    const schoolId = 2;

    let dateCondition = '';
    if (days !== '999999') {
      dateCondition = `AND b.created_at >= NOW() - INTERVAL '${parseInt(days)} days'`;
    }

    let typeCondition = '';
    if (type !== 'all') {
      typeCondition = `AND b.booking_type = '${type}'`;
    }

    let outcomeCondition = '';
    if (outcome !== 'all') {
      if (outcome === 'no_response') {
        outcomeCondition = `AND bo.outcome_status IS NULL`;
      } else {
        outcomeCondition = `AND bo.outcome_status = '${outcome}'`;
      }
    }

    let entryYearCondition = '';
    if (entryYear !== 'all') {
      entryYearCondition = `AND i.entry_year = '${entryYear}'`;
    }

    // Get summary counts
    const summaryResult = await pool.query(`
      SELECT
        COUNT(CASE WHEN bo.outcome_status = 'interested' THEN 1 END) as interested,
        COUNT(CASE WHEN bo.outcome_status = 'applied' THEN 1 END) as applied,
        COUNT(CASE WHEN bo.outcome_status = 'enrolled' THEN 1 END) as enrolled,
        COUNT(CASE WHEN bo.outcome_status = 'declined' THEN 1 END) as declined,
        COUNT(CASE WHEN bo.outcome_status IS NULL THEN 1 END) as no_response
      FROM bookings b
      LEFT JOIN booking_outcomes bo ON bo.booking_id = b.id
      LEFT JOIN inquiries i ON b.inquiry_id = i.id
      WHERE b.school_id = $1
        AND b.status = 'confirmed'
        AND b.checked_in_at IS NOT NULL
        ${dateCondition}
        ${typeCondition}
        ${outcomeCondition}
        ${entryYearCondition}
    `, [schoolId]);

    // Get detailed outcomes
    const outcomesResult = await pool.query(`
      WITH booking_ratings AS (
        SELECT
          booking_id,
          ROUND(AVG(rating_value)::numeric, 1) as avg_rating
        FROM feedback_responses
        WHERE rating_value IS NOT NULL
        GROUP BY booking_id
      )
      SELECT DISTINCT ON (b.id)
        b.id,
        b.parent_first_name || ' ' || b.parent_last_name as parent_name,
        b.student_first_name || ' ' || COALESCE(b.student_last_name, '') as student_name,
        COALESCE(e.event_date, b.scheduled_date) as tour_date,
        b.booking_type,
        e.title as event_title,
        tg.name as guide_name,
        bo.outcome_status,
        i.entry_year,
        bo.outcome_date,
        bo.notes,
        EXISTS(SELECT 1 FROM feedback_responses WHERE booking_id = b.id) as feedback_submitted,
        br.avg_rating,
        b.created_at,
        bo.updated_at
      FROM bookings b
      LEFT JOIN events e ON e.id = b.event_id
      LEFT JOIN tour_guides tg ON tg.id = b.assigned_guide_id
      LEFT JOIN booking_outcomes bo ON bo.booking_id = b.id
      LEFT JOIN inquiries i ON b.inquiry_id = i.id
      LEFT JOIN booking_ratings br ON br.booking_id = b.id
      WHERE b.school_id = $1
        AND b.status = 'confirmed'
        AND b.checked_in_at IS NOT NULL
        ${dateCondition}
        ${typeCondition}
        ${outcomeCondition}
        ${entryYearCondition}
      ORDER BY b.id, bo.updated_at DESC NULLS LAST, b.created_at DESC
      LIMIT 100
    `, [schoolId]);

    res.json({
      success: true,
      summary: summaryResult.rows[0],
      outcomes: outcomesResult.rows
    });
  } catch (error) {
    console.error('Get conversion outcomes error:', error);
    res.status(500).json({ success: false, error: 'Failed to get conversion outcomes' });
  }
});

// ==================== AUTOMATED EMAIL SCHEDULER ====================

// Helper function to get template ID by booking type and template type
async function getTemplateId(bookingType, templateType, schoolId = 2) {
  try {
    const result = await pool.query(
      `SELECT id FROM email_templates
       WHERE school_id = $1
       AND (booking_type = $2 OR booking_type = 'both')
       AND template_type = $3
       AND is_active = true
       ORDER BY booking_type DESC
       LIMIT 1`,
      [schoolId, bookingType, templateType]
    );

    if (result.rows.length === 0) {
      console.error(`No template found for booking_type: ${bookingType}, template_type: ${templateType}`);
      return null;
    }

    return result.rows[0].id;
  } catch (error) {
    console.error('Error getting template ID:', error);
    return null;
  }
}

// Helper function to send template-based email
async function sendTemplateEmail(booking, templateId, emailType, smartFeedback = null) {
  try {
    // Fetch template
    const template = await pool.query('SELECT * FROM email_templates WHERE id = $1', [templateId]);
    if (template.rows.length === 0) {
      console.error(`Template ${templateId} not found`);
      return false;
    }

    // Ensure booking has a feedback_token (generate if missing)
    let feedbackToken = booking.feedback_token;
    if (!feedbackToken) {
      feedbackToken = crypto.randomBytes(32).toString('hex');
      await pool.query(
        'UPDATE bookings SET feedback_token = $1 WHERE id = $2',
        [feedbackToken, booking.id]
      );
      console.log(`✓ Generated feedback token for booking #${booking.id}`);
    }

    // Prepare template data
    const eventDate = booking.event_date || booking.scheduled_date;
    const eventTime = booking.start_time || booking.scheduled_time;
    // Use appropriate feedback form based on booking type
    const feedbackFormPage = booking.booking_type === 'taster_day'
      ? 'taster-feedback-form.html'
      : booking.booking_type === 'open_day'
      ? 'tour-feedback-form.html'
      : 'tour-feedback-form.html'; // Default for private tours
    const feedbackUrl = `${process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com'}/${feedbackFormPage}?token=${feedbackToken}`;

    // Determine pronouns based on gender
    // Default to 'she/her' for More House School (girls' school)
    let pronounSubject = 'she';
    let pronounObject = 'her';
    let pronounPossessive = 'her';

    if (booking.gender) {
      const gender = booking.gender.toLowerCase();
      if (gender === 'male' || gender === 'm' || gender === 'boy') {
        pronounSubject = 'he';
        pronounObject = 'him';
        pronounPossessive = 'his';
      } else if (gender === 'female' || gender === 'f' || gender === 'girl') {
        pronounSubject = 'she';
        pronounObject = 'her';
        pronounPossessive = 'her';
      }
    }

    // Format the date nicely
    const formattedDate = eventDate ? new Date(eventDate).toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : '';

    const templateData = {
      booking_id: booking.id,
      parent_name: `${booking.parent_first_name} ${booking.parent_last_name || ''}`.trim(),
      parent_first_name: booking.parent_first_name || '',
      student_name: `${booking.student_first_name} ${booking.student_last_name || ''}`.trim(),
      student_first_name: booking.student_first_name || '',
      child_name: booking.student_first_name || '',
      school_name: 'More House School',
      tour_date: formattedDate,
      tour_time: eventTime || '',
      event_date: formattedDate,
      scheduled_date: formattedDate,
      start_time: eventTime || '',
      event_title: booking.event_title || booking.title || 'your scheduled visit',
      num_attendees: booking.num_attendees || 1,
      tour_guide: booking.guide_name || 'our tour guide',
      guide_name: booking.guide_name || 'our tour guide',
      feedback_link: feedbackUrl,
      pronoun_subject: pronounSubject,
      pronoun_object: pronounObject,
      pronoun_possessive: pronounPossessive
    };

    // Add SMART Feedback data if provided
    if (smartFeedback) {
      // Format key_interests as natural language list
      if (smartFeedback.key_interests && Array.isArray(smartFeedback.key_interests) && smartFeedback.key_interests.length > 0) {
        const interests = smartFeedback.key_interests;
        if (interests.length === 1) {
          templateData.key_interests = interests[0];
        } else if (interests.length === 2) {
          templateData.key_interests = `${interests[0]} and ${interests[1]}`;
        } else {
          templateData.key_interests = `${interests.slice(0, -1).join(', ')}, and ${interests[interests.length - 1]}`;
        }
      } else {
        templateData.key_interests = '';
      }
    }

    // Replace template variables
    let subject = template.rows[0].subject;
    let body = template.rows[0].body;

    // Step 1: Replace variables FIRST
    Object.keys(templateData).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      subject = subject.replace(regex, templateData[key]);
      body = body.replace(regex, templateData[key]);
    });

    // Step 2: Handle conditionals AFTER variable replacement
    body = body.replace(/\{\{#if\s+(\w+)\}\}([\s\S]*?)(?:\{\{else\}\}([\s\S]*?))?\{\{\/if\}\}/g, (match, variable, ifContent, elseContent) => {
      const value = templateData[variable];
      if (value && value !== '' && value !== '0' && value !== 'false') {
        return ifContent;
      } else {
        return elseContent || '';
      }
    });

    // Step 3: Convert URLs to button-ready format
    // Replace standalone URLs with a special marker we can detect later
    body = body.replace(/^(https?:\/\/[^\s]+)$/gm, '|||BUTTON_LINK|||$1|||');

    // Convert plain text body to formatted HTML - keeps template editable by staff
    // Simply formats paragraphs and converts feedback URLs to clickable buttons
    const htmlBody = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
              line-height: 1.6;
              color: #2C3E50;
              margin: 0;
              padding: 0;
              background-color: #F8FAFC;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
            }
            .content {
              padding: 40px 30px;
            }
            p {
              margin: 15px 0;
              font-size: 16px;
              color: #475569;
              line-height: 1.6;
            }
            a.button {
              display: inline-block;
              background: #FF9F1C;
              color: #091825 !important;
              padding: 14px 28px;
              text-decoration: none;
              border-radius: 6px;
              margin: 20px 0;
              font-weight: 600;
              font-size: 16px;
              transition: all 0.3s ease;
            }
            a.button:hover {
              background: #E68A00;
              transform: translateY(-2px);
              box-shadow: 0 4px 12px rgba(255, 159, 28, 0.3);
            }
            .footer {
              text-align: center;
              margin-top: 30px;
              padding: 30px;
              border-top: 1px solid #E5E7EB;
              background: #F8FAFC;
            }
            .footer p {
              margin: 5px 0;
              font-size: 14px;
              color: #64748B;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="content">
              ${body.split('\n\n').map((para, index, array) => {
                const trimmed = para.trim();
                if (!trimmed) return '';

                // Convert feedback URL to clickable button
                const urlMatch = trimmed.match(/(https?:\/\/[^\s]+)/);
                if (urlMatch) {
                  const url = urlMatch[1];
                  let buttonText = 'Click Here';
                  let descriptionText = '';

                  const textBefore = trimmed.substring(0, trimmed.indexOf(url)).trim();
                  const textAfter = trimmed.substring(trimmed.indexOf(url) + url.length).trim();

                  // If no text before URL in current paragraph, check previous paragraph
                  if (!textBefore && index > 0) {
                    const previousPara = array[index - 1].trim();
                    if (previousPara) {
                      const sentences = previousPara.split(/[.!?]\s+/);
                      descriptionText = sentences[sentences.length - 1].trim();
                    }
                  } else if (textBefore) {
                    // Extract the last sentence or phrase before the URL as description
                    const sentences = textBefore.split(/[.!?]\s+/);
                    descriptionText = sentences[sentences.length - 1].trim();
                  }

                  // Common patterns for button text extraction
                  if (descriptionText.toLowerCase().includes('submit feedback') ||
                      descriptionText.toLowerCase().includes('share your feedback') ||
                      descriptionText.toLowerCase().includes('share feedback')) {
                    buttonText = 'Submit Feedback';
                  } else if (descriptionText.toLowerCase().includes('complete our feedback') ||
                             descriptionText.toLowerCase().includes('feedback survey')) {
                    buttonText = 'Complete Survey';
                  } else if (descriptionText.toLowerCase().includes('view') && descriptionText.toLowerCase().includes('crm')) {
                    buttonText = 'View in CRM';
                  } else if (descriptionText.toLowerCase().includes('application') ||
                             descriptionText.toLowerCase().includes('apply')) {
                    buttonText = 'Apply Now';
                  } else if (descriptionText.toLowerCase().includes('read more') ||
                             descriptionText.toLowerCase().includes('learn more')) {
                    buttonText = 'Learn More';
                  }

                  return `
                    ${textBefore ? `<p>${textBefore}</p>` : ''}
                    <div style="text-align: center; margin: 30px 0;">
                      <a href="${url}" class="button">${buttonText}</a>
                    </div>
                    ${textAfter ? `<p>${textAfter}</p>` : ''}
                  `;
                }

                // Convert line breaks within paragraphs
                return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
              }).join('')}
            </div>
            <div class="footer">
              <p style="font-weight: 600; color: #091825; font-size: 16px;">More House School</p>
              <p>22-24 Pont Street, Knightsbridge, London, SW1X 0AA</p>
              <p>Tel: 020 7235 2855 | Email: office@morehousemail.org.uk</p>
            </div>
          </div>
        </body>
      </html>
    `;

    // Send email via email worker for branded template
    await emailWorker.sendEmail({
      to: booking.email,
      subject: subject,
      text: body,
      html: htmlBody
    });

    // Mark as sent in scheduled_emails
    await pool.query(
      'UPDATE scheduled_emails SET status = $1, sent_at = CURRENT_TIMESTAMP WHERE booking_id = $2 AND email_type = $3',
      ['sent', booking.id, emailType]
    );

    console.log(`✓ Sent ${emailType} email to ${booking.email} for booking #${booking.id}`);
    return true;
  } catch (error) {
    console.error(`Failed to send ${emailType} email for booking #${booking.id}:`, error);

    // Log error in scheduled_emails
    await pool.query(
      'UPDATE scheduled_emails SET status = $1, error_message = $2 WHERE booking_id = $3 AND email_type = $4',
      ['failed', error.message, booking.id, emailType]
    ).catch(e => console.error('Failed to log error:', e));

    return false;
  }
}

// Helper function to send internal staff emails using templates
async function sendInternalTemplateEmail(templateId, recipientEmail, templateData, attachments = [], ccEmail = null) {
  try {
    // Fetch template
    const template = await pool.query('SELECT * FROM email_templates WHERE id = $1', [templateId]);
    if (template.rows.length === 0) {
      console.error(`Template ${templateId} not found`);
      return false;
    }

    // Replace template variables
    let subject = template.rows[0].subject;
    let body = template.rows[0].body;

    // Step 1: Replace variables FIRST
    Object.keys(templateData).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      subject = subject.replace(regex, templateData[key] || '');
      body = body.replace(regex, templateData[key] || '');
    });

    // Step 2: Handle conditionals AFTER variable replacement
    body = body.replace(/\{\{#if\s+(\w+)\}\}([\s\S]*?)(?:\{\{else\}\}([\s\S]*?))?\{\{\/if\}\}/g, (match, variable, ifContent, elseContent) => {
      const value = templateData[variable];
      if (value && value !== '' && value !== '0' && value !== 'false') {
        return ifContent;
      } else {
        return elseContent || '';
      }
    });

    // Convert plain text body to formatted HTML
    const htmlBody = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; background: white; }
            .header { background: #091825; color: white; padding: 30px; text-align: center; border-bottom: 3px solid #FF9F1C; }
            .header h1 { margin: 0; font-size: 24px; }
            .content { padding: 20px; }
            p { margin: 10px 0; }
            a.button { display: inline-block; background: #FF9F1C; color: white !important; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 15px 0; font-weight: 600; }
            a.button:hover { background: #e68a0f; }
            .footer { text-align: center; margin-top: 30px; padding: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>More House School</h1>
            </div>
            <div class="content">
              ${body.split('\n\n').map((para, index, array) => {
                const trimmed = para.trim();
                if (!trimmed) return '';

                // Convert URLs to clickable buttons with smart label extraction
                const urlMatch = trimmed.match(/(https?:\/\/[^\s]+)/);
                if (urlMatch) {
                  const url = urlMatch[1];
                  let buttonText = 'Click Here';
                  let descriptionText = '';

                  // Check if there's text before the URL in the same paragraph
                  const textBeforeUrl = trimmed.substring(0, trimmed.indexOf(urlMatch[0])).trim();

                  // If no text before URL in current paragraph, check previous paragraph
                  if (!textBeforeUrl && index > 0) {
                    const previousPara = array[index - 1].trim();
                    if (previousPara) {
                      const sentences = previousPara.split(/[.!?]\s+/);
                      descriptionText = sentences[sentences.length - 1].trim();
                    }
                  } else if (textBeforeUrl) {
                    // Extract the last sentence or phrase before the URL as description
                    const sentences = textBeforeUrl.split(/[.!?]\s+/);
                    descriptionText = sentences[sentences.length - 1].trim();
                  }

                  // Common patterns for button text extraction
                  if (descriptionText.toLowerCase().includes('submit feedback') ||
                      descriptionText.toLowerCase().includes('share your feedback') ||
                      descriptionText.toLowerCase().includes('share feedback')) {
                    buttonText = 'Submit Feedback';
                  } else if (descriptionText.toLowerCase().includes('complete our feedback') ||
                             descriptionText.toLowerCase().includes('feedback survey')) {
                    buttonText = 'Complete Survey';
                  } else if (descriptionText.toLowerCase().includes('view') && descriptionText.toLowerCase().includes('crm')) {
                    buttonText = 'View in CRM';
                  } else if (descriptionText.toLowerCase().includes('application') ||
                             descriptionText.toLowerCase().includes('apply')) {
                    buttonText = 'Apply Now';
                  } else if (descriptionText.toLowerCase().includes('read more') ||
                             descriptionText.toLowerCase().includes('learn more')) {
                    buttonText = 'Learn More';
                  }

                  // Build the output - only show description text if it's in the same paragraph
                  let output = '';
                  if (textBeforeUrl) {
                    output += `<p>${textBeforeUrl}</p>`;
                  }
                  output += `<p style="text-align: center; margin-top: 15px;"><a href="${url}" class="button">${buttonText}</a></p>`;

                  return output;
                }

                return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
              }).join('')}
            </div>
            <div class="footer">
              <p>More House School<br>
              22-24 Pont Street, Knightsbridge, London, SW1X 0AA<br>
              Tel: 020 7235 2855 | Email: office@morehousemail.org.uk</p>
            </div>
          </div>
        </body>
      </html>
    `;

    // Send email
    const mailOptions = {
      from: `"More House School" <${process.env.GMAIL_USER}>`,
      to: recipientEmail,
      subject: subject,
      text: body,
      html: htmlBody,
      attachments: attachments
    };

    // Add CC if provided
    if (ccEmail) {
      mailOptions.cc = ccEmail;
    }

    await (await getEmailTransporter()).sendMail(mailOptions);

    const ccLog = ccEmail ? ` (CC: ${ccEmail})` : '';
    console.log(`✓ Sent internal email (template ${templateId}) to ${recipientEmail}${ccLog}`);
    return true;
  } catch (error) {
    console.error(`Failed to send internal email (template ${templateId}):`, error);
    return false;
  }
}

// ============================================================================
// AUTOMATED EMAIL SYSTEM - Uses template automation_days settings
// ============================================================================

// Process all automated emails based on template settings
async function processAutomatedEmails() {
  try {
    console.log('\n[Email Automation] Processing automated emails based on template settings...');

    // Get all active templates with automation enabled
    const templatesResult = await pool.query(`
      SELECT id, name, booking_type, template_type, automation_trigger, automation_days, automation_timing
      FROM email_templates
      WHERE school_id = 2
        AND is_active = true
        AND enable_automation = true
        AND automation_trigger IS NOT NULL
      ORDER BY id
    `);

    console.log(`[Email Automation] Found ${templatesResult.rows.length} automated templates`);

    for (const template of templatesResult.rows) {
      await processTemplateAutomation(template);
    }
  } catch (error) {
    console.error('[Email Automation] Error:', error);
  }
}

// Process a single template's automation
async function processTemplateAutomation(template) {
  const { id: templateId, name, booking_type, template_type, automation_trigger, automation_days, automation_timing } = template;

  try {
    // Skip templates without proper timing config for scheduled emails
    if (automation_trigger === 'before_tour' && automation_days === null) {
      return;
    }

    let bookings = [];
    let emailType = template_type;

    // Handle different automation triggers
    switch (automation_trigger) {
      case 'before_tour':
        // Reminder emails X days before the tour/event
        bookings = await getBookingsForReminder(booking_type, automation_days, emailType, templateId);
        break;

      case 'on_check_in':
        // Follow-up emails X days after check-in
        if (automation_timing === 'after' && automation_days !== null) {
          bookings = await getBookingsForFollowUp(booking_type, automation_days, emailType, templateId);
        }
        break;

      case 'on_no_show':
        // No-show follow-up emails X days after the event
        if (automation_days !== null) {
          bookings = await getBookingsForNoShowFollowUp(booking_type, automation_days, emailType, templateId);
        }
        break;

      // Event-triggered emails (on_booking, on_decline, on_schedule, etc.)
      // are handled in their respective API endpoints, not in cron
      default:
        return;
    }

    if (bookings.length > 0) {
      console.log(`[${name}] Processing ${bookings.length} booking(s)`);
    }

    for (const booking of bookings) {
      // Check if this is a guide reminder (internal template)
      if (template_type === 'internal' && automation_trigger === 'before_tour') {
        await processGuideReminder(booking, template);
      } else {
        await sendAutomatedEmail(booking, templateId, emailType);
      }
    }
  } catch (error) {
    console.error(`[${name}] Error:`, error.message);
  }
}

// Get bookings that need reminder emails (X days before tour)
async function getBookingsForReminder(bookingType, daysBefore, emailType, templateId) {
  const emailTypeKey = daysBefore >= 5 ? 'reminder_first' : 'reminder_final';

  // Build booking type filter
  let bookingTypeFilter = '';
  if (bookingType === 'open_day') {
    bookingTypeFilter = "AND b.booking_type = 'open_day'";
  } else if (bookingType === 'private_tour') {
    bookingTypeFilter = "AND b.booking_type = 'private_tour'";
  } else if (bookingType === 'taster_day') {
    bookingTypeFilter = "AND b.booking_type = 'taster_day'";
  }

  const result = await pool.query(`
    SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
           tg.name as guide_name, tg.email as guide_email
    FROM bookings b
    LEFT JOIN events e ON b.event_id = e.id
    LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
    WHERE b.school_id = 2
      AND b.status = 'confirmed'
      ${bookingTypeFilter}
      AND (
        (e.event_date = CURRENT_DATE + INTERVAL '1 day' * $1)
        OR (b.scheduled_date = CURRENT_DATE + INTERVAL '1 day' * $1)
      )
      AND NOT EXISTS (
        SELECT 1 FROM scheduled_emails
        WHERE booking_id = b.id
        AND template_id = $2
        AND status IN ('sent', 'pending')
      )
    ORDER BY b.id
  `, [daysBefore, templateId]);

  return result.rows;
}

// Get bookings that need follow-up emails (X days after check-in)
async function getBookingsForFollowUp(bookingType, daysAfter, emailType, templateId) {
  let bookingTypeFilter = '';
  if (bookingType === 'open_day') {
    bookingTypeFilter = "AND b.booking_type = 'open_day'";
  } else if (bookingType === 'private_tour') {
    bookingTypeFilter = "AND b.booking_type = 'private_tour'";
  } else if (bookingType === 'taster_day') {
    bookingTypeFilter = "AND b.booking_type = 'taster_day'";
  }

  const result = await pool.query(`
    SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
           tg.name as guide_name, i.gender
    FROM bookings b
    LEFT JOIN events e ON b.event_id = e.id
    LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
    LEFT JOIN inquiries i ON b.inquiry_id = i.id
    WHERE b.school_id = 2
      AND b.checked_in_at IS NOT NULL
      ${bookingTypeFilter}
      AND (
        (e.event_date = CURRENT_DATE - INTERVAL '1 day' * $1)
        OR (b.scheduled_date = CURRENT_DATE - INTERVAL '1 day' * $1)
      )
      AND NOT EXISTS (
        SELECT 1 FROM scheduled_emails
        WHERE booking_id = b.id
        AND template_id = $2
        AND status IN ('sent', 'pending')
      )
    ORDER BY b.id
  `, [daysAfter, templateId]);

  return result.rows;
}

// Get bookings that need no-show follow-up emails
async function getBookingsForNoShowFollowUp(bookingType, daysAfter, emailType, templateId) {
  let bookingTypeFilter = '';
  if (bookingType === 'open_day') {
    bookingTypeFilter = "AND b.booking_type = 'open_day'";
  } else if (bookingType === 'private_tour') {
    bookingTypeFilter = "AND b.booking_type = 'private_tour'";
  } else if (bookingType === 'taster_day') {
    bookingTypeFilter = "AND b.booking_type = 'taster_day'";
  }

  const result = await pool.query(`
    SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
           tg.name as guide_name
    FROM bookings b
    LEFT JOIN events e ON b.event_id = e.id
    LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
    WHERE b.school_id = 2
      AND b.no_show_at IS NOT NULL
      ${bookingTypeFilter}
      AND (
        (e.event_date = CURRENT_DATE - INTERVAL '1 day' * $1)
        OR (b.scheduled_date = CURRENT_DATE - INTERVAL '1 day' * $1)
      )
      AND NOT EXISTS (
        SELECT 1 FROM scheduled_emails
        WHERE booking_id = b.id
        AND template_id = $2
        AND status IN ('sent', 'pending')
      )
    ORDER BY b.id
  `, [daysAfter, templateId]);

  return result.rows;
}

// Process guide reminder (internal email to tour guide)
async function processGuideReminder(booking, template) {
  if (!booking.guide_email) return;

  const guide = { name: booking.guide_name, email: booking.guide_email };
  const notificationType = template.automation_days >= 5 ? 'reminder_first' : 'reminder_final';

  await sendTourGuideNotification(booking, guide, notificationType);

  // Log in scheduled_emails
  await pool.query(
    `INSERT INTO scheduled_emails (booking_id, email_type, scheduled_for, template_id, status, sent_at)
     VALUES ($1, $2, CURRENT_TIMESTAMP, $3, 'sent', CURRENT_TIMESTAMP)
     ON CONFLICT (booking_id, email_type) DO NOTHING`,
    [booking.id, `guide_${notificationType}`, template.id]
  );
}

// Send automated email using template
async function sendAutomatedEmail(booking, templateId, emailType) {
  try {
    // Log in scheduled_emails
    await pool.query(
      `INSERT INTO scheduled_emails (booking_id, email_type, scheduled_for, template_id, status)
       VALUES ($1, $2, CURRENT_TIMESTAMP, $3, 'pending')
       ON CONFLICT (booking_id, email_type) DO NOTHING`,
      [booking.id, emailType, templateId]
    );

    await sendTemplateEmail(booking, templateId, emailType);

    console.log(`  ✓ Sent ${emailType} email to ${booking.email} (booking #${booking.id})`);
  } catch (error) {
    console.error(`  ✗ Failed ${emailType} for booking #${booking.id}:`, error.message);
  }
}

// Legacy function wrappers for backward compatibility
async function send7DayReminders() {
  // Now handled by processAutomatedEmails()
  console.log('[First Reminder] Using unified automation system');
}

async function send1DayReminders() {
  // Now handled by processAutomatedEmails()
  console.log('[Second Reminder] Using unified automation system');
}

async function sendFollowUpEmails() {
  // Now handled by processAutomatedEmails()
  console.log('[Follow-ups] Using unified automation system');
}

async function sendNoShowFollowUps() {
  // Now handled by processAutomatedEmails()
  console.log('[No-show Follow-ups] Using unified automation system');
}

async function sendGuideFirstReminders() {
  // Now handled by processAutomatedEmails()
  console.log('[Guide First Reminder] Using unified automation system');
}

async function sendGuideFinalReminders() {
  // Now handled by processAutomatedEmails()
  console.log('[Guide Final Reminder] Using unified automation system');
}

// Run email scheduler every hour - uses unified processAutomatedEmails()
cron.schedule('0 * * * *', async () => {
  console.log('\n========================================');
  console.log(`Running automated email scheduler at ${new Date().toLocaleString()}`);
  console.log('========================================');

  await processAutomatedEmails();

  console.log('========================================\n');
});

// Run once on startup (for testing/immediate execution)
setTimeout(async () => {
  console.log('\n[Startup] Running initial email check...');
  await processAutomatedEmails();
}, 5000);

// Test email template
app.post('/api/email-templates/:id/test', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { testEmail } = req.body;

    if (!testEmail) {
      return res.status(400).json({ success: false, error: 'testEmail is required' });
    }

    // Fetch template
    const template = await pool.query('SELECT * FROM email_templates WHERE id = $1', [id]);
    if (template.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }

    // Sample data for template variables - comprehensive list
    const sampleData = {
      parent_name: 'Andrew Anderson',
      student_name: 'Anna Anderson',
      school_name: 'More House School',
      email: 'andrew.anderson@example.com',
      phone: '020 7123 4567',
      tour_date: 'Monday, 15th December 2025',
      tour_time: '10:00 AM - 11:30 AM',
      num_attendees: '3',
      tour_guide: 'John Smith',
      guide_name: 'John Smith',
      event_title: 'December Open Day',
      event_date: 'Monday, 15th December 2025',
      event_time: '10:00 AM - 12:00 PM',
      start_time: '10:00 AM',
      end_time: '12:00 PM',
      scheduled_date: 'Monday, 15th December 2025',
      scheduled_time: '10:00 AM',
      special_requirements: 'Wheelchair access required',
      preferred_language: 'English',
      status: 'Confirmed',
      booked_at: 'Monday, 17th November 2025 at 5:15 PM',
      cancellation_link: `${process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com'}/cancel/sample-token-123`,
      feedback_link: `${process.env.APP_URL || 'https://smart-bookings-more-house.onrender.com'}/tour-feedback-form.html?token=sample-token-456`,
      pronoun_possessive: 'her',
      pronoun_object: 'her',
      key_interests: 'mathematics and science',
      parent_email: 'andrew.anderson@example.com',
      parent_phone: '020 7123 4567'
    };

    // Replace template variables
    let subject = template.rows[0].subject;
    let body = template.rows[0].body;

    // Step 1: Replace variables FIRST
    Object.keys(sampleData).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      subject = subject.replace(regex, sampleData[key]);
      body = body.replace(regex, sampleData[key]);
    });

    // Step 2: Handle conditionals AFTER variable replacement
    body = body.replace(/\{\{#if\s+(\w+)\}\}([\s\S]*?)(?:\{\{else\}\}([\s\S]*?))?\{\{\/if\}\}/g, (match, variable, ifContent, elseContent) => {
      const value = sampleData[variable];
      if (value && value !== '' && value !== '0' && value !== 'false') {
        return ifContent;
      } else {
        return elseContent || '';
      }
    });

    // Convert plain text body to formatted HTML with orange button styling
    const htmlBody = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; background: white; }
            .header { background: #091825; color: white; padding: 30px; text-align: center; border-bottom: 3px solid #FF9F1C; }
            .header h1 { margin: 0; font-size: 24px; }
            .content { padding: 20px; }
            p { margin: 10px 0; }
            a.button { display: inline-block; background: #FF9F1C; color: white !important; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 15px 0; font-weight: 600; }
            a.button:hover { background: #e68a0f; }
            .footer { text-align: center; margin-top: 30px; padding: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>More House School</h1>
            </div>
            <div class="content">
              ${body.split('\n\n').map((para, index, array) => {
                const trimmed = para.trim();
                if (!trimmed) return '';

                // Convert URLs to clickable buttons with smart label extraction
                const urlMatch = trimmed.match(/(https?:\/\/[^\s]+)/);
                if (urlMatch) {
                  const url = urlMatch[1];
                  let buttonText = 'Click Here';
                  let descriptionText = '';

                  const textBeforeUrl = trimmed.substring(0, trimmed.indexOf(urlMatch[0])).trim();

                  // If no text before URL in current paragraph, check previous paragraph
                  if (!textBeforeUrl && index > 0) {
                    const previousPara = array[index - 1].trim();
                    if (previousPara) {
                      const sentences = previousPara.split(/[.!?]\s+/);
                      descriptionText = sentences[sentences.length - 1].trim();
                    }
                  } else if (textBeforeUrl) {
                    const sentences = textBeforeUrl.split(/[.!?]\s+/);
                    descriptionText = sentences[sentences.length - 1].trim();
                  }

                  // Common patterns for button text extraction
                  if (descriptionText.toLowerCase().includes('submit feedback') ||
                      descriptionText.toLowerCase().includes('share your feedback') ||
                      descriptionText.toLowerCase().includes('share feedback')) {
                    buttonText = 'Submit Feedback';
                  } else if (descriptionText.toLowerCase().includes('complete our feedback') ||
                             descriptionText.toLowerCase().includes('feedback survey')) {
                    buttonText = 'Complete Survey';
                  } else if (descriptionText.toLowerCase().includes('view') && descriptionText.toLowerCase().includes('crm')) {
                    buttonText = 'View in CRM';
                  } else if (descriptionText.toLowerCase().includes('application') ||
                             descriptionText.toLowerCase().includes('apply')) {
                    buttonText = 'Apply Now';
                  } else if (descriptionText.toLowerCase().includes('read more') ||
                             descriptionText.toLowerCase().includes('learn more')) {
                    buttonText = 'Learn More';
                  }

                  let output = '';
                  if (textBeforeUrl) {
                    output += `<p>${textBeforeUrl}</p>`;
                  }
                  output += `<p style="text-align: center; margin-top: 15px;"><a href="${url}" class="button">${buttonText}</a></p>`;

                  return output;
                }

                return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
              }).join('')}
            </div>
            <div class="footer">
              <p>More House School<br>
              22-24 Pont Street, Knightsbridge, London, SW1X 0AA<br>
              Tel: 020 7235 2855 | Email: office@morehousemail.org.uk</p>
            </div>
          </div>
        </body>
      </html>
    `;

    // Send email
    await (await getEmailTransporter()).sendMail({
      from: process.env.GMAIL_USER,
      to: testEmail,
      subject: subject,
      text: body,
      html: htmlBody
    });

    res.json({
      success: true,
      message: 'Test email sent successfully',
      templateName: template.rows[0].name,
      sentTo: testEmail
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ====================================================
// TOUR GUIDE FEEDBACK ENDPOINTS
// ====================================================

// Get all tour feedback form fields
app.get('/api/tour-feedback-fields', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId = 2, tourType } = req.query;

    let query = `SELECT * FROM tour_feedback_form_fields WHERE school_id = $1`;
    const params = [schoolId];

    // Filter by tour_type if provided
    if (tourType) {
      query += ` AND tour_type = $2`;
      params.push(tourType);
    }

    query += ` ORDER BY display_order ASC`;

    const result = await pool.query(query, params);

    res.json({ success: true, fields: result.rows });
  } catch (error) {
    console.error('Get tour feedback fields error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch fields' });
  }
});

// Get all taster day feedback form fields
app.get('/api/taster-feedback-fields', requireAdminAuth, async (req, res) => {
  try {
    const { schoolId = 2 } = req.query;

    const result = await pool.query(
      `SELECT fq.*
       FROM feedback_questions fq
       JOIN feedback_forms ff ON fq.form_id = ff.id
       WHERE ff.school_id = $1
         AND ff.form_type = 'taster_day'
         AND fq.is_active = true
       ORDER BY fq.display_order ASC`,
      [schoolId]
    );

    res.json({ success: true, fields: result.rows });
  } catch (error) {
    console.error('[TASTER FEEDBACK FIELDS] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch taster feedback fields' });
  }
});

// Get feedback questions by form type (for settings page)
app.get('/api/feedback-questions', async (req, res) => {
  try {
    const { schoolId = 2, formType } = req.query;

    if (!formType) {
      return res.status(400).json({ success: false, error: 'formType is required' });
    }

    const result = await pool.query(
      `SELECT fq.*
       FROM feedback_questions fq
       JOIN feedback_forms ff ON fq.form_id = ff.id
       WHERE ff.school_id = $1
         AND ff.form_type = $2
         AND fq.is_active = true
       ORDER BY fq.display_order ASC`,
      [schoolId, formType]
    );

    res.json({ success: true, questions: result.rows });
  } catch (error) {
    console.error('[FEEDBACK QUESTIONS] Error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch feedback questions' });
  }
});

// Create a new tour feedback field
app.post('/api/tour-feedback-fields', requireAdminAuth, async (req, res) => {
  try {
    const {
      field_name,
      field_label,
      field_type,
      field_options,
      is_required = false,
      placeholder,
      help_text,
      school_id = 2
    } = req.body;

    if (!field_name || !field_label || !field_type) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    // Get max display_order
    const maxOrderResult = await pool.query(
      'SELECT COALESCE(MAX(display_order), -1) + 1 as next_order FROM tour_feedback_form_fields WHERE school_id = $1',
      [school_id]
    );
    const displayOrder = maxOrderResult.rows[0].next_order;

    const result = await pool.query(
      `INSERT INTO tour_feedback_form_fields
       (school_id, field_name, field_label, field_type, field_options, is_required, placeholder, help_text, display_order)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [school_id, field_name, field_label, field_type, field_options, is_required, placeholder, help_text, displayOrder]
    );

    res.json({ success: true, field: result.rows[0] });
  } catch (error) {
    console.error('Create tour feedback field error:', error);
    res.status(500).json({ success: false, error: 'Failed to create field' });
  }
});

// Update a tour feedback field
app.put('/api/tour-feedback-fields/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      field_label,
      field_type,
      field_options,
      is_required,
      placeholder,
      help_text
    } = req.body;

    const result = await pool.query(
      `UPDATE tour_feedback_form_fields
       SET field_label = $1,
           field_type = $2,
           field_options = $3,
           is_required = $4,
           placeholder = $5,
           help_text = $6,
           updated_at = NOW()
       WHERE id = $7
       RETURNING *`,
      [field_label, field_type, field_options, is_required, placeholder, help_text, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Field not found' });
    }

    res.json({ success: true, field: result.rows[0] });
  } catch (error) {
    console.error('Update tour feedback field error:', error);
    res.status(500).json({ success: false, error: 'Failed to update field' });
  }
});

// Delete a tour feedback field
app.delete('/api/tour-feedback-fields/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM tour_feedback_form_fields WHERE id = $1 RETURNING *',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Field not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Delete tour feedback field error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete field' });
  }
});

// Reorder tour feedback fields
app.post('/api/tour-feedback-fields/reorder', requireAdminAuth, async (req, res) => {
  try {
    const { updates } = req.body; // Array of {id, display_order}

    for (const update of updates) {
      await pool.query(
        'UPDATE tour_feedback_form_fields SET display_order = $1, updated_at = NOW() WHERE id = $2',
        [update.display_order, update.id]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Reorder tour feedback fields error:', error);
    res.status(500).json({ success: false, error: 'Failed to reorder fields' });
  }
});

// Submit tour guide feedback
app.post('/api/tour-feedback/submit', async (req, res) => {
  try {
    const { token, responses } = req.body;

    if (!token || !responses) {
      return res.status(400).json({
        success: false,
        error: 'Missing token or responses'
      });
    }

    // Find booking by feedback token
    const bookingResult = await pool.query(
      'SELECT id, assigned_guide_id FROM bookings WHERE feedback_token = $1',
      [token]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invalid or expired feedback token'
      });
    }

    const booking = bookingResult.rows[0];

    // Count existing submissions for this booking
    const countResult = await pool.query(
      'SELECT COUNT(*) as count FROM tour_guide_feedback WHERE booking_id = $1',
      [booking.id]
    );
    const submissionNumber = parseInt(countResult.rows[0].count) + 1;

    // Insert feedback
    const result = await pool.query(
      `INSERT INTO tour_guide_feedback (booking_id, guide_id, submission_number, responses)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [booking.id, booking.assigned_guide_id, submissionNumber, JSON.stringify(responses)]
    );

    // Get booking and guide details for notification email
    const detailsResult = await pool.query(
      `SELECT b.*, tg.name as guide_name, tg.email as guide_email,
              e.title as event_title, e.event_date, e.start_time,
              i.gender
       FROM bookings b
       LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
       LEFT JOIN events e ON b.event_id = e.id
       LEFT JOIN inquiries i ON b.inquiry_id = i.id
       WHERE b.id = $1`,
      [booking.id]
    );

    const bookingDetails = detailsResult.rows[0];

    // Send notification email to admissions team (async, don't wait)
    sendFeedbackNotification(bookingDetails, responses, submissionNumber).catch(err => {
      console.error('Error sending feedback notification:', err);
    });

    // Send personalized follow-up email to parent (only on first submission)
    if (submissionNumber === 1) {
      console.log(`[SMART FEEDBACK] Attempting to send follow-up email for booking #${booking.id}, submission #${submissionNumber}`);
      try {
        const templateId = bookingDetails.booking_type === 'open_day' ? 5 : 11; // Follow-up template IDs
        console.log(`[SMART FEEDBACK] Using template ID ${templateId} for ${bookingDetails.booking_type}`);
        console.log(`[SMART FEEDBACK] Recipient: ${bookingDetails.email}`);

        // Send personalized email with SMART Feedback data
        await sendTemplateEmail(bookingDetails, templateId, 'followup', responses);

        console.log(`[SMART FEEDBACK] ✓ Personalized follow-up email sent to ${bookingDetails.email} for booking #${bookingDetails.id}`);
      } catch (emailError) {
        console.error('[SMART FEEDBACK] ❌ Failed to send follow-up email:', emailError);
        console.error('[SMART FEEDBACK] Error stack:', emailError.stack);
        // Don't fail the whole request if email fails
      }
    } else {
      console.log(`[SMART FEEDBACK] Skipping follow-up email - not first submission (submission #${submissionNumber})`);
    }

    res.json({ success: true, feedback: result.rows[0] });
  } catch (error) {
    console.error('Submit tour feedback error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit feedback' });
  }
});

// Get feedback for a booking
app.get('/api/bookings/:id/tour-feedback', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT tf.*, tg.name as guide_name
       FROM tour_guide_feedback tf
       LEFT JOIN tour_guides tg ON tf.guide_id = tg.id
       WHERE tf.booking_id = $1
       ORDER BY tf.submitted_at DESC`,
      [id]
    );

    res.json({ success: true, feedback: result.rows });
  } catch (error) {
    console.error('Get tour feedback error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch feedback' });
  }
});

// Submit taster day feedback
app.post('/api/feedback/taster', async (req, res) => {
  try {
    const { token, responses } = req.body;

    if (!token || !responses) {
      return res.status(400).json({
        success: false,
        error: 'Missing token or responses'
      });
    }

    // Find booking by feedback token
    const bookingResult = await pool.query(
      'SELECT id, assigned_guide_id, booking_type FROM bookings WHERE feedback_token = $1 AND booking_type = $2',
      [token, 'taster_day']
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invalid or expired feedback token'
      });
    }

    const booking = bookingResult.rows[0];

    // Count existing submissions for this booking
    const countResult = await pool.query(
      'SELECT COUNT(*) as count FROM tour_guide_feedback WHERE booking_id = $1',
      [booking.id]
    );
    const submissionNumber = parseInt(countResult.rows[0].count) + 1;

    // Insert feedback (note: guide_id can be null for taster days if no guide assigned)
    const result = await pool.query(
      `INSERT INTO tour_guide_feedback (booking_id, guide_id, submission_number, responses)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [booking.id, booking.assigned_guide_id, submissionNumber, JSON.stringify(responses)]
    );

    // Get booking and guide details for notification email
    const detailsResult = await pool.query(
      `SELECT b.*, tg.name as guide_name, tg.email as guide_email,
              e.title as event_title, e.event_date, e.start_time,
              i.gender
       FROM bookings b
       LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
       LEFT JOIN events e ON b.event_id = e.id
       LEFT JOIN inquiries i ON b.inquiry_id = i.id
       WHERE b.id = $1`,
      [booking.id]
    );

    const bookingDetails = detailsResult.rows[0];

    // Send notification email to admissions team (async, don't wait)
    sendFeedbackNotification(bookingDetails, responses, submissionNumber).catch(err => {
      console.error('Error sending feedback notification:', err);
    });

    // Send personalized follow-up email to parent (only on first submission)
    if (submissionNumber === 1) {
      console.log(`[SMART FEEDBACK - TASTER] Attempting to send follow-up email for booking #${booking.id}, submission #${submissionNumber}`);
      try {
        // Template ID 14 for taster day follow-up (you may need to adjust this based on your templates)
        const templateId = 14;
        console.log(`[SMART FEEDBACK - TASTER] Using template ID ${templateId} for ${bookingDetails.booking_type}`);
        console.log(`[SMART FEEDBACK - TASTER] Recipient: ${bookingDetails.email}`);

        // Send personalized email with SMART Feedback data
        await sendTemplateEmail(bookingDetails, templateId, 'followup', responses);

        console.log(`[SMART FEEDBACK - TASTER] ✓ Personalized follow-up email sent to ${bookingDetails.email} for booking #${bookingDetails.id}`);
      } catch (emailError) {
        console.error('[SMART FEEDBACK - TASTER] ❌ Failed to send follow-up email:', emailError);
        console.error('[SMART FEEDBACK - TASTER] Error stack:', emailError.stack);
        // Don't fail the whole request if email fails
      }
    } else {
      console.log(`[SMART FEEDBACK - TASTER] Skipping follow-up email - not first submission (submission #${submissionNumber})`);
    }

    res.json({ success: true, feedback: result.rows[0] });
  } catch (error) {
    console.error('Submit taster day feedback error:', error);
    res.status(500).json({ success: false, error: 'Failed to submit feedback' });
  }
});

// Get taster day feedback for a booking
app.get('/api/bookings/:id/taster-feedback', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT tf.*, tg.name as guide_name
       FROM tour_guide_feedback tf
       LEFT JOIN tour_guides tg ON tf.guide_id = tg.id
       LEFT JOIN bookings b ON tf.booking_id = b.id
       WHERE tf.booking_id = $1 AND b.booking_type = 'taster_day'
       ORDER BY tf.submitted_at DESC`,
      [id]
    );

    res.json({ success: true, feedback: result.rows });
  } catch (error) {
    console.error('Get taster day feedback error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch feedback' });
  }
});

// ============================================
// TOUR GUIDE BRIEFING CARDS
// ============================================

// Get all bookings for an event with full details for briefing cards
app.get('/api/events/:id/briefing-cards', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.query;

    // Get event details
    const eventResult = await pool.query(
      'SELECT * FROM events WHERE id = $1',
      [id]
    );

    if (eventResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }

    const event = eventResult.rows[0];

    // Get school settings for logo
    const settingsResult = await pool.query(
      'SELECT school_name, logo_url, logo_data FROM booking_settings WHERE school_id = $1',
      [event.school_id || 2]
    );
    const settingsRow = settingsResult.rows[0] || {};
    // Use logo_data (base64) if available, otherwise logo_url
    const settings = {
      ...settingsRow,
      logo_url: settingsRow.logo_data || settingsRow.logo_url
    };

    // Get all bookings for this event with full inquiry data (same query as /api/bookings)
    let bookingsQuery = `
      SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
             tg.name as guide_name,
             i.age_group, i.entry_year, i.sciences, i.mathematics, i.english, i.languages, i.humanities,
             i.business, i.drama, i.music, i.art, i.creative_writing, i.sport,
             i.leadership, i.community_service, i.outdoor_education, i.academic_excellence,
             i.pastoral_care, i.university_preparation, i.personal_development,
             i.career_guidance, i.extracurricular_opportunities, i.hear_about_us
      FROM bookings b
      LEFT JOIN events e ON b.event_id = e.id
      LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
      LEFT JOIN inquiries i ON (b.inquiry_id = i.id OR (b.email = i.parent_email AND i.first_name = b.student_first_name))
      WHERE b.event_id = $1
    `;

    const params = [id];

    // Filter by status if provided (default to confirmed bookings)
    if (status) {
      bookingsQuery += ` AND b.status = $2`;
      params.push(status);
    } else {
      bookingsQuery += ` AND b.status IN ('confirmed', 'checked_in')`;
    }

    bookingsQuery += ` ORDER BY b.id, tg.name ASC NULLS LAST, b.parent_last_name ASC`;

    const bookingsResult = await pool.query(bookingsQuery, params);

    // Get notes and email history for each booking (using same queries as existing endpoints)
    const bookingsWithFullData = await Promise.all(
      bookingsResult.rows.map(async (booking) => {
        // Get notes - same as /api/bookings/:id/notes
        let notes = [];
        if (booking.inquiry_id) {
          const notesResult = await pool.query(
            `SELECT
              n.id,
              n.note_text as content,
              n.created_at,
              n.created_by,
              CONCAT(creator.first_name, ' ', creator.last_name) as admin_name,
              creator.email as created_by_email
            FROM inquiry_notes n
            LEFT JOIN admin_users creator ON n.created_by = creator.id
            WHERE n.inquiry_id = $1
            ORDER BY n.created_at DESC`,
            [booking.inquiry_id]
          );
          notes = notesResult.rows;
        }

        // Get email history - same as /api/bookings/:id/email-history
        let emails = [];
        if (booking.inquiry_id) {
          // Get regular email history
          const emailResult = await pool.query(
            `SELECT
              id,
              enquiry_id,
              direction,
              from_email,
              from_name,
              to_email,
              to_name,
              subject,
              body_text,
              sent_at,
              received_at,
              admin_email
            FROM email_history
            WHERE enquiry_id = $1 AND is_deleted = false
            ORDER BY COALESCE(sent_at, received_at) ASC`,
            [booking.inquiry_id]
          );

          // Also get AI-generated email history
          const aiEmailResult = await pool.query(
            `SELECT
              id,
              inquiry_id as enquiry_id,
              parent_email as from_email,
              parent_name as from_name,
              '' as to_email,
              '' as to_name,
              '' as subject,
              original_email_text as original_text,
              generated_email as body_text,
              created_at as sent_at,
              sentiment_score,
              sentiment_label,
              sentiment_reasoning,
              'ai-generated' as direction
            FROM email_generation_history
            WHERE inquiry_id = $1
            ORDER BY created_at ASC`,
            [booking.inquiry_id]
          );

          // Combine both results
          const allEmails = [...emailResult.rows, ...aiEmailResult.rows].sort((a, b) => {
            const timeA = new Date(a.sent_at || a.received_at);
            const timeB = new Date(b.sent_at || b.received_at);
            return timeA - timeB;
          });
          emails = allEmails;
        }

        // Get prospectus viewing visits from tracking_events table (same as admin app SMART Tracking)
        let visits = [];
        if (booking.inquiry_id) {
          // Get all tracking events for this inquiry
          const eventsResult = await pool.query(`
            SELECT
              session_id,
              event_type,
              timestamp,
              country,
              event_data
            FROM tracking_events
            WHERE inquiry_id = $1
            ORDER BY session_id, timestamp ASC
          `, [booking.inquiry_id]);

          // Group events by session_id to create visits
          const sessionsMap = new Map();

          for (const event of eventsResult.rows) {
            const sessionId = event.session_id;
            if (!sessionsMap.has(sessionId)) {
              sessionsMap.set(sessionId, {
                session_id: sessionId,
                started_at: event.timestamp,
                ended_at: event.timestamp,
                country: event.country,
                sections: [],
                total_time: 0
              });
            }

            const session = sessionsMap.get(sessionId);
            session.ended_at = event.timestamp;

            // Track section views with dwell time
            if ((event.event_type === 'section_exit' || event.event_type === 'section_exit_enhanced') && event.event_data) {
              const section = event.event_data.section;
              const dwellSec = parseFloat(event.event_data.dwellSec) || 0;
              if (section) {
                session.sections.push({
                  section: section,
                  time_spent: dwellSec
                });
                session.total_time += dwellSec;
              }
            }
          }

          // Convert to array and sort by start time descending
          visits = Array.from(sessionsMap.values())
            .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
            .map((visit, index, arr) => ({
              ...visit,
              visit_number: arr.length - index
            }));
        }

        return {
          ...booking,
          notes: notes,
          email_history: emails,
          visits: visits
        };
      })
    );

    // Group bookings by tour guide for easier distribution
    const byGuide = {};
    bookingsWithFullData.forEach(booking => {
      const guideName = booking.guide_name || 'Unassigned';
      if (!byGuide[guideName]) {
        byGuide[guideName] = [];
      }
      byGuide[guideName].push(booking);
    });

    res.json({
      success: true,
      event: event,
      settings: settings,
      bookings: bookingsWithFullData,
      bookingsByGuide: byGuide,
      totalFamilies: bookingsWithFullData.length,
      totalGuides: Object.keys(byGuide).length
    });

  } catch (error) {
    console.error('Get briefing cards error:', error);
    res.status(500).json({ success: false, error: 'Failed to get briefing cards data' });
  }
});

// Get single booking briefing card data (for Private Tours and Taster Days)
app.get('/api/bookings/:id/briefing-card', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Get booking with full details (same query pattern as briefing-cards)
    const bookingResult = await pool.query(`
      SELECT DISTINCT ON (b.id) b.*, e.title as event_title, e.event_date, e.start_time,
             tg.name as guide_name,
             i.age_group, i.entry_year, i.sciences, i.mathematics, i.english, i.languages, i.humanities,
             i.business, i.drama, i.music, i.art, i.creative_writing, i.sport,
             i.leadership, i.community_service, i.outdoor_education, i.academic_excellence,
             i.pastoral_care, i.university_preparation, i.personal_development,
             i.career_guidance, i.extracurricular_opportunities, i.hear_about_us
      FROM bookings b
      LEFT JOIN events e ON b.event_id = e.id
      LEFT JOIN tour_guides tg ON b.assigned_guide_id = tg.id
      LEFT JOIN inquiries i ON (b.inquiry_id = i.id OR (b.email = i.parent_email AND i.first_name = b.student_first_name))
      WHERE b.id = $1
    `, [id]);

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    const booking = bookingResult.rows[0];

    // Get school settings for logo
    const settingsResult = await pool.query(
      'SELECT school_name, logo_url, logo_data FROM booking_settings WHERE school_id = $1',
      [booking.school_id || 2]
    );
    const settingsRow = settingsResult.rows[0] || {};
    const settings = {
      ...settingsRow,
      logo_url: settingsRow.logo_data || settingsRow.logo_url
    };

    // Get notes
    let notes = [];
    if (booking.inquiry_id) {
      const notesResult = await pool.query(
        `SELECT
          n.id,
          n.note_text as content,
          n.created_at,
          n.created_by,
          CONCAT(creator.first_name, ' ', creator.last_name) as admin_name,
          creator.email as created_by_email
        FROM inquiry_notes n
        LEFT JOIN admin_users creator ON n.created_by = creator.id
        WHERE n.inquiry_id = $1
        ORDER BY n.created_at DESC`,
        [booking.inquiry_id]
      );
      notes = notesResult.rows;
    }

    // Get email history
    let emails = [];
    if (booking.inquiry_id) {
      const emailResult = await pool.query(
        `SELECT
          id,
          enquiry_id,
          direction,
          from_email,
          from_name,
          to_email,
          to_name,
          subject,
          body_text,
          sent_at,
          received_at,
          admin_email
        FROM email_history
        WHERE enquiry_id = $1 AND is_deleted = false
        ORDER BY COALESCE(sent_at, received_at) ASC`,
        [booking.inquiry_id]
      );

      const aiEmailResult = await pool.query(
        `SELECT
          id,
          inquiry_id as enquiry_id,
          parent_email as from_email,
          parent_name as from_name,
          '' as to_email,
          '' as to_name,
          '' as subject,
          original_email_text as original_text,
          generated_email as body_text,
          created_at as sent_at,
          sentiment_score,
          sentiment_label,
          sentiment_reasoning,
          'ai-generated' as direction
        FROM email_generation_history
        WHERE inquiry_id = $1
        ORDER BY created_at ASC`,
        [booking.inquiry_id]
      );

      const allEmails = [...emailResult.rows, ...aiEmailResult.rows].sort((a, b) => {
        const timeA = new Date(a.sent_at || a.received_at);
        const timeB = new Date(b.sent_at || b.received_at);
        return timeA - timeB;
      });
      emails = allEmails;
    }

    // Get prospectus viewing visits from tracking_events table
    let visits = [];
    if (booking.inquiry_id) {
      const eventsResult = await pool.query(`
        SELECT
          session_id,
          event_type,
          timestamp,
          country,
          event_data
        FROM tracking_events
        WHERE inquiry_id = $1
        ORDER BY session_id, timestamp ASC
      `, [booking.inquiry_id]);

      const sessionsMap = new Map();

      for (const event of eventsResult.rows) {
        const sessionId = event.session_id;
        if (!sessionsMap.has(sessionId)) {
          sessionsMap.set(sessionId, {
            session_id: sessionId,
            started_at: event.timestamp,
            ended_at: event.timestamp,
            country: event.country,
            sections: [],
            total_time: 0
          });
        }

        const session = sessionsMap.get(sessionId);
        session.ended_at = event.timestamp;

        if ((event.event_type === 'section_exit' || event.event_type === 'section_exit_enhanced') && event.event_data) {
          const section = event.event_data.section;
          const dwellSec = parseFloat(event.event_data.dwellSec) || 0;
          if (section) {
            session.sections.push({
              section: section,
              time_spent: dwellSec
            });
            session.total_time += dwellSec;
          }
        }
      }

      visits = Array.from(sessionsMap.values())
        .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
        .map((visit, index, arr) => ({
          ...visit,
          visit_number: arr.length - index
        }));
    }

    const bookingWithFullData = {
      ...booking,
      notes: notes,
      email_history: emails,
      visits: visits
    };

    res.json({
      success: true,
      booking: bookingWithFullData,
      settings: settings
    });

  } catch (error) {
    console.error('Get single briefing card error:', error);
    res.status(500).json({ success: false, error: 'Failed to get briefing card data' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`Booking server running on http://localhost:${PORT}`);

  // Sync admin users from environment variables to database
  try {
    await syncAdminUsersToDatabase();
  } catch (error) {
    console.error('[BOOKING APP] Failed to sync admin users:', error.message);
  }
});
