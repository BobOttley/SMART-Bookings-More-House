# More House Booking Platform - Technical Features Summary

## SYSTEM ARCHITECTURE

**Tech Stack:**
- Node.js + Express.js web server
- PostgreSQL database (shared with SMART CRM)
- Email: SMTP (configurable) + Gmail fallback
- Authentication: Session-based (express-session with database store)
- Templating: HTML/JSON responses (API-driven)
- Frontend: Vanilla JavaScript + HTML5

**Running on:** Port 3002 (Render.com cloud deployment)

---

## CORE FEATURES AT A GLANCE

### 1. BOOKING MANAGEMENT
- 3 booking types: Open Days, Private Tours, Taster Days
- 6 booking statuses: pending, confirmed, declined, cancelled, checked_in, no_show
- Parent self-service booking via public form
- Staff-created bookings for flexibility
- Booking cancellation with token-based authentication
- Alternative date offer & acceptance workflow

### 2. EVENT MANAGEMENT
- Create/update/delete events
- Capacity tracking (auto-updates with bookings)
- Event date/time scheduling
- Soft-delete support (archive old events)
- Multi-type support (open day, taster day, private tour)
- Feedback form assignment per event

### 3. TOUR GUIDE MANAGEMENT
- Create/update/delete guides
- Email and phone contact tracking
- Guide type classification
- Active/inactive status
- Multiple guides per event
- Automatic notification on assignment

### 4. EMAIL SYSTEM

**Architecture:**
- Dynamic SMTP configuration (database-driven)
- Fallback to environment Gmail
- Template-based email generation
- Merge field substitution
- HTML generation from plain text
- Smart button creation from URLs
- Calendar invite generation (iCal .ics format)
- Email logging & duplicate prevention
- CC capability

**Automated Emails (Hourly Cron):**
- 7-day pre-visit reminder (configurable)
- 1-day pre-visit reminder (configurable)
- Post-visit follow-up (configurable days)
- No-show follow-up (within 24 hours)
- Guide first reminder (configurable)
- Guide final reminder (configurable)

**Manual Emails:**
- Send any template on demand
- Personalized with booking data
- Test email sending before saving

### 5. FEEDBACK COLLECTION

**Two-Tier System:**

**A. Tour Guide Feedback (SMART Feedback)**
- Custom form fields configurable by admin
- JSON response storage
- Multiple submissions per booking
- Timestamp tracking
- Guide observations on student & parent
- Optional taster day specific forms

**B. Family Survey Responses**
- Standard feedback forms per booking type
- Rating questions (1-5 scale)
- Text response questions
- Multiple choice options
- Unique feedback token per booking
- Response tracking

**Feedback Triggers:**
- Sent to family 1 day after visit (configurable)
- Tour guide sends observations anytime
- Admin notified when feedback received
- Personalized follow-up sent to parent after guide feedback

### 6. ANALYTICS & CONVERSION TRACKING

**Real-Time Metrics:**
- Total bookings by type/status
- Feedback response rate %
- Average satisfaction rating (1-5)
- Conversion rate (feedback received → enrolled)
- Question-by-question breakdown
- Rating distribution (5/5, 4/5, etc.)

**Outcome Tracking:**
- Interested (family interested in school)
- Applied (submitted application)
- Enrolled (student enrolled)
- Declined (family decided against)
- No response (outcome not yet recorded)

**Conversion Analytics:**
- Detailed journey tracking (interested → enrolled)
- Entry year filtering
- Booking type filtering
- Time period filtering (30/60/all days)
- Family-level outcome tracking
- Guide performance metrics

### 7. ADMINISTRATIVE FEATURES

**Booking Details Page:**
- Complete family/student information
- Contact details and preferences
- Special requirements capture
- Email communication history
- Internal notes (shared with CRM)
- Attached documents/files
- Prospectus visit tracking
- Feedback submissions
- Outcome recording

**Briefing Cards:**
- For open days: All families grouped by guide
- For private tours: Single booking details
- Print-friendly format
- Family background & interests
- Email history summary
- Internal notes
- Special requirements highlighted
- Prospectus visit analysis
- Guide preparation tool

**Check-in System:**
- Timestamp recording
- Admin attribution
- Batch check-in capability
- Automatic follow-up email triggers
- Analytics qualification

### 8. FORM BUILDER

**Customizable Inquiry Forms:**
- Text, textarea, email, phone fields
- Dropdown, checkbox, radio options
- Date and number fields
- Conditional display (show for gender)
- Required field validation
- Help text and placeholders
- Custom display ordering
- Section grouping
- Auto-mapping to inquiry columns

### 9. SETTINGS & CONFIGURATION

**Configurable Parameters:**
- Reminder timing (days before event)
- Follow-up timing (days after event)
- No-show follow-up timing
- Guide reminder timing
- SMTP server configuration
- School branding (logo)
- Email from address/name

**Admin Accessible Settings:**
- Email templates management
- Feedback question configuration
- Tour guide list management
- Event scheduling
- Booking settings
- Prospectus integration

### 10. AUTHENTICATION & SECURITY

**Login System:**
- Session-based authentication
- BCrypt password hashing
- 24-hour session timeout
- Permission checking (can_access_booking)
- Admin user management
- Password reset flow

**Access Control:**
- All admin endpoints protected with requireAdminAuth
- Public endpoints for parent self-service
- Token-based verification for parent actions
- Unique tokens: feedback_token, cancellation_token, response_token

**Data Privacy:**
- Session storage in database
- No password storage in plain text
- Unique tokens per booking
- HTTPS enforced in production

---

## API ENDPOINT CATEGORIES

### Bookings (20+ endpoints)
- CRUD operations
- Special actions: assign-guide, schedule, decline, check-in, reassign-guide, no-show, accept-alternative
- Status updates
- Outcome tracking
- Note management
- Email history
- Feedback retrieval

### Events (5 endpoints)
- Create, read, update, delete
- Assign feedback form
- Listing with filtering
- Capacity management

### Tour Guides (4 endpoints)
- Create, read, update, delete
- Active/inactive status
- Contact information

### Email (7 endpoints)
- Template CRUD
- Template testing
- Email configuration (SMTP)
- Email settings management

### Feedback (15+ endpoints)
- Form management
- Question management
- Response submission
- Feedback retrieval
- Analytics queries

### Settings (8+ endpoints)
- Booking settings
- Email settings
- Logo upload
- Form template management
- Form field management

### Analytics (3 endpoints)
- Feedback statistics
- Question-by-question breakdown
- Conversion outcomes

### Authentication (5 endpoints)
- Login/logout
- Auth check
- Password reset
- Session management

---

## DATABASE INTEGRATION

**Shared Tables (with SMART CRM):**
- admin_users (authentication)
- inquiries (parent/student information)
- inquiry_notes (internal notes)
- email_history (communication log)
- tracking_events (prospectus visits)

**Booking App Tables:**
- bookings (core booking data)
- events (event scheduling)
- tour_guides (guide management)
- email_templates (email configuration)
- tour_guide_feedback (guide observations)
- feedback_responses (family survey responses)
- feedback_forms (form configuration)
- feedback_questions (question configuration)
- booking_outcomes (conversion tracking)
- booking_email_logs (email tracking)
- scheduled_emails (automation queue)
- enquiry_form_templates (custom form builder)
- enquiry_form_fields (form field definitions)
- enquiry_form_sections (form organization)
- booking_settings (school configuration)

---

## KEY INTEGRATIONS

### SMART CRM Integration
- Shared user authentication
- Inquiry data synchronization
- Note storage & retrieval
- Email history integration
- Admin user management

### Prospectus Tracking
- Embedded tracking_events table
- Session identification
- Section visit tracking
- Dwell time measurement
- Display on briefing cards

---

## AUTOMATION & SCHEDULING

**Cron Jobs:**
- Runs hourly (0 * * * *) - Automated email sending
- Runs at startup (5 second delay) - Initial email check
- Configurable timing for all automated emails

**Automated Actions:**
- Booking confirmation email
- Pre-visit reminders (2 stages)
- Post-visit follow-up
- Guide notifications (assignment + reminders)
- Admissions team notifications
- No-show follow-up
- Outcome tracking workflows

---

## FRONTEND PAGES

### Admin Dashboard (index.html)
- Tabbed interface with 7 main tabs
- Responsive design
- Drag-to-reorder tabs
- Sub-tabs for settings
- Real-time data updates
- Quick action buttons

### Public Booking Form (book.html)
- Event selection
- Family details collection
- Student information
- Special requirements
- Form validation
- Confirmation

### Feedback Forms
- tour-feedback-form.html (guide feedback)
- taster-feedback-form.html (taster day feedback)
- Unique token-based access
- Rating scales
- Text responses
- Progress tracking

### Other Pages
- respond.html - Alternative date acceptance
- book-verify.html - Confirmation page
- briefing-card.html - Guide preparation
- briefing-cards.html - Event overview
- feedback-analytics.html - Reports dashboard
- login.html - Authentication
- reset-password.html - Password recovery

---

## CONFIGURATION FILES

**.env Variables:**
- PORT, DATABASE_URL, GMAIL_USER, GMAIL_APP_PASSWORD
- EMAIL_FROM, SESSION_SECRET, ADMIN_EMAIL
- APP_URL, BASE_URL, CRM_URL

**Database Settings (booking_settings table):**
- SMTP configuration (host, port, username, password)
- Reminder timing (days before event)
- Follow-up timing (days after)
- School branding (logo, name)

---

## PERFORMANCE & SCALABILITY

**Database Optimizations:**
- Connection pooling (pg library)
- Indexed queries on common fields
- Prepared statements for security
- Query result caching not implemented (real-time data)

**Email Performance:**
- Asynchronous email sending
- Cron-based batch processing
- Email queue with status tracking
- Duplicate prevention via scheduled_emails table

**Session Management:**
- Session store in database (persistent)
- 24-hour expiration
- Secure cookie handling

---

## SECURITY FEATURES

**Password Security:**
- BCrypt hashing (10 rounds)
- Unique salts per password
- No plain text storage

**Token Generation:**
- Cryptographically secure tokens (crypto.randomBytes)
- Unique per booking
- Time-based expiration possible (not implemented)

**SQL Injection Prevention:**
- Parameterized queries throughout
- No string concatenation in SQL
- Pool connection security

**CSRF Protection:**
- Session-based authentication
- Cookie-based sessions
- SameSite attributes

**Data Privacy:**
- No sensitive data in logs
- Email logging without body content
- Token rotation on sensitive actions

---

## DEPENDENCIES

**Core:**
- express (4.18.2) - Web framework
- pg (8.11.3) - PostgreSQL client
- express-session (1.17.3) - Session management
- connect-pg-simple (9.0.1) - Session store

**Email:**
- nodemailer (6.9.7) - Email sending

**Utilities:**
- bcrypt (5.1.1) - Password hashing
- dotenv (16.3.1) - Environment variables
- multer (2.0.2) - File uploads (logo)
- node-cron (4.2.1) - Job scheduling

**Misc:**
- cors (2.8.5) - CORS handling
- crypto (1.0.1) - Token generation

---

## ERROR HANDLING

**General Pattern:**
- Try/catch on all async operations
- Meaningful error messages to admins
- Logging of errors to console
- HTTP status codes (400, 404, 500)
- JSON error responses

**Email Failures:**
- Non-blocking (errors logged, request continues)
- Retry on next cron run
- Fallback email settings

**Database Failures:**
- Connection pooling with retries
- Error propagation to client
- Logging for debugging

---

## TESTING

**Test Email Capability:**
- Send test email via `/api/email-templates/:id/test`
- Sample data provided
- Actual template rendering tested
- Merge field substitution verified

---

## DEPLOYMENT

**Current:** Render.com
- Node.js runtime
- PostgreSQL database (separate)
- Environment variables configured
- HTTPS enforced

**Production Settings:**
- Email from: bob.ottley@morehousemail.org.uk
- Base URL: https://smart-bookings-more-house.onrender.com
- CRM URL: https://smart-crm-more-house.onrender.com
- Session secure cookies enabled

---

## MONITORING & LOGGING

**Console Logging:**
- Admin login attempts
- Email sending status
- Cron job execution
- Error stack traces
- Booking status changes
- Guide notifications

**Database Logging:**
- Email logs (booking_email_logs)
- Scheduled email status
- Booking history (created_at, updated_at)
- Note timestamps

---

## FUTURE ENHANCEMENT OPPORTUNITIES

- SMS notifications for reminders
- WhatsApp integration for tour guides
- QR code check-in system
- Video tour recording links
- Virtual tour platform integration
- Advanced analytics dashboards
- Predictive modeling for conversions
- Parent mobile app
- Guide mobile app
- Webhook system for external integrations

---

**Technical Documentation Version:** 1.0
**Last Updated:** December 2024
**Platform:** Node.js/Express/PostgreSQL
