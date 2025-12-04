# More House School Booking Platform - Comprehensive Feature Documentation

## System Overview
The More House Booking App is a Node.js/Express application that manages school visits (tours, open days, and taster days). It includes:
- Admin dashboard for managing bookings
- Event and tour guide management
- Automated email communications
- Feedback collection systems
- Booking analytics and conversion tracking
- Prospectus integration

---

## 1. CORE BOOKING TYPES

### Open Days
- Multi-family group visits on a scheduled date
- Families book slots for specific open day events
- Multiple tour guides can lead simultaneous tours
- Capacity tracking per event

### Private Tours
- One-on-one scheduled tours with families
- Flexible scheduling by admissions staff
- Individual guide assignment
- Custom timing per tour

### Taster Days
- Specific student visit experiences
- May include academic sessions
- Guide feedback collection
- Enrollment tracking

---

## 2. EVENT MANAGEMENT

### Creating/Managing Events
**Endpoints:**
- `POST /api/events` - Create new event
- `GET /api/events` - List all events (with filtering)
- `GET /api/events/:id` - Get event details
- `PUT /api/events/:id` - Update event
- `DELETE /api/events/:id` - Delete event

**Event Fields:**
- Event Type (open_day, taster_day, private_tour)
- Title & Description
- Event Date & Time (start_time, end_time)
- Capacity Management (max_capacity, current_bookings)
- Active status

**Features:**
- Soft delete support (can exclude deleted events from listings)
- Event date filtering
- Capacity tracking (bookings update count automatically)
- Status tracking

### Assigning Feedback Forms to Events
- `PUT /api/events/:id/assign-form` - Link feedback form to event
- Allows different feedback questions per event type
- Tour guides use assigned form when submitting feedback

---

## 3. BOOKING MANAGEMENT

### Booking Statuses
- `pending` - Initial inquiry received
- `confirmed` - Scheduled and confirmed
- `declined` - Declined by admissions (with alternative dates offered)
- `cancelled` - Cancelled by parent or staff
- `checked_in` - Family arrived and checked in
- `no_show` - Family did not attend

### Creating Bookings

**Staff Creation (Admin Only):**
- `POST /api/bookings/staff-create` - Create booking on behalf of family
- Requires: parent name/email, student details, booking type, scheduled date/time
- Auto-generates cancellation and feedback tokens

**Parent Self-Service:**
- Form submission via public form
- Creates inquiry first, then booking
- Automatic confirmation email

### Managing Bookings

**Key Endpoints:**
- `GET /api/bookings` - List all bookings (with comprehensive filtering)
- `GET /api/bookings/:id` - Get booking details
- `POST /api/bookings` - Create from inquiry
- `PUT /api/bookings/:id` - Update booking
- `PUT /api/bookings/:id/staff-edit` - Staff update with validation
- `DELETE /api/bookings/:id` - Delete booking

**Booking Fields:**
- Parent: first_name, last_name, email, phone
- Student: first_name, last_name, age_group, entry_year
- Visit: booking_type, scheduled_date, scheduled_time
- Event: event_id (for open days/taster days)
- Attendance: checked_in_at, checked_in_by
- Guide: assigned_guide_id
- Tracking: cancellation_token, feedback_token, response_token
- Preferences: special_requirements, preferred_language
- Relationships: inquiry_id (links to CRM inquiries)

### Special Booking Actions

**Reassign Guide:**
- `POST /api/bookings/:id/reassign-guide`
- Removes previous guide assignment
- Auto-generates feedback token if needed
- Sends assignment notification to new guide

**Schedule Tour:**
- `POST /api/bookings/:id/schedule`
- Sets scheduled_date, scheduled_time
- Assigns guide if provided
- Sends confirmation email to parent
- Sends calendar invite to tour guide (iCal format)

**Decline with Alternatives:**
- `POST /api/bookings/:id/decline`
- Marks as "declined"
- Offers alternative dates/times
- Parent receives response link to accept alternative

**Accept Alternative:**
- `POST /api/bookings/accept-alternative`
- Parent accepts offered alternative date
- Status changes to "confirmed"
- Sends confirmation email

**Mark No-Show:**
- `PUT /api/bookings/:id/no-show`
- Records no-show_at timestamp
- Triggers no-show follow-up email (configurable days)
- Updates analytics

**Check-In:**
- `POST /api/bookings/:id/checkin`
- Records checked_in_at timestamp and checked_in_by (staff member)
- Marks family as arrived
- Used to qualify for feedback/follow-up emails

**Update Status:**
- `PUT /api/bookings/:id/status`
- Direct status change
- Updates updated_at timestamp

**Cancel Booking:**
- `POST /api/bookings/cancel` (public endpoint)
- Parent uses cancellation_token
- Reason tracking
- Updates event booking count

### Booking Filtering & Searching
- By status, booking type, date range
- By tour guide assignment
- By event
- Checked-in status
- Feedback submitted status

---

## 4. CHECKING IN FAMILIES

**Check-in Endpoint:**
- `POST /api/bookings/:id/checkin`
- Records timestamp and admin who checked them in
- Triggers eligibility for:
  - Feedback response tracking
  - Follow-up emails
  - Analytics inclusion

**Check-in UI Features (in Dashboard):**
- List confirmed bookings
- Filter by event or tour guide
- Quick check-in button
- Timestamp recording
- Integration with tours view

**Briefing Cards for Open Days:**
- `GET /api/events/:id/briefing-cards`
- Shows all confirmed/checked-in bookings for event
- Grouped by tour guide
- Includes:
  - Family contact information
  - Student details & interests
  - Special requirements
  - Email history
  - Prospectus viewing visits
  - Internal notes

---

## 5. TOUR GUIDE MANAGEMENT

### Creating Tour Guides
- `POST /api/tour-guides`
- Fields: name, email, phone, type (standard guide, staff, etc.)
- school_id for multi-school support
- is_active flag for soft deletion

### Managing Tour Guides
- `GET /api/tour-guides` - List all guides
- `PUT /api/tour-guides/:id` - Update guide details
- `DELETE /api/tour-guides/:id` - Delete guide

### Guide Notifications

**Assignment Notification:**
- Sent when guide assigned to booking
- Includes:
  - Booking/tour details
  - Family information
  - Student details
  - Number of attendees
  - Special requirements
  - Feedback form link
- Attachments: iCal calendar invite (.ics format)
- Automatic reminders before tour

**Reminder Emails (Configurable):**
- `reminder_first` - 3 days before (configurable via guide_reminder_days_before_1)
- `reminder_final` - 1 day before (configurable via guide_reminder_days_before_2)
- Can enable/disable via settings

**Template IDs for Guides:**
- 28: Tour Guide - Assignment (with calendar invite)
- 29: Tour Guide - First Reminder
- 30: Tour Guide - Final Reminder

---

## 6. EMAIL TEMPLATES & COMMUNICATIONS

### Template System Architecture

**Templates Table Fields:**
- id, school_id, name, booking_type, template_type
- subject, body, is_active
- enable_automation, automation_trigger, automation_days, automation_timing
- created_at, updated_at

**Template Types:**
- `confirmation` - Tour confirmed
- `reminder_7day` - First reminder (open days/private tours)
- `reminder_1day` - Final reminder before event
- `followup` - Post-visit follow-up with feedback request
- `decline` - Tour declined with alternatives
- `no_show` - No-show follow-up
- `admissions_notification` - Notify admissions of booking
- `guide_assigned` - Notify guide of assignment
- `guide_removed` - Notify guide of unassignment
- `feedback_submitted` - Feedback received notification
- Other custom types

### Predefined Template IDs (Hard-coded)
- **Open Days:**
  - 1: Confirmation
  - 3: First Reminder (7 days before)
  - 4: Final Reminder (1 day before)
  - 5: Follow-up (1 day after)
  - 12: No-Show Follow-up
  - 16: Decline with Alternatives
  
- **Private Tours:**
  - 7: Confirmation
  - 9: First Reminder (7 days before)
  - 10: Final Reminder (1 day before)
  - 11: Follow-up (1 day after)
  - 13: No-Show Follow-up
  - 17: Decline with Alternatives
  
- **Taster Days:**
  - 14: Follow-up (1 day after)
  
- **Guides:**
  - 28: Assignment (with calendar invite)
  - 29: First Reminder
  - 30: Final Reminder
  
- **Admin:**
  - 31: Feedback Notification to Admissions Team
  - Others for admissions_notification per booking type

### Email Template Management

**Endpoints:**
- `GET /api/email-templates` - List templates for school
- `POST /api/email-templates` - Create new template
- `PUT /api/email-templates/:id` - Update template
- `DELETE /api/email-templates/:id` - Delete template
- `POST /api/email-templates/:id/test` - Send test email

### Template Variables (Merge Fields)
Available for use in subject and body:
- `{parent_name}`, `{parent_email}`, `{parent_phone}`
- `{student_name}`, `{student_first_name}`, `{student_last_name}`
- `{email}`, `{phone}`, `{num_attendees}`
- `{tour_date}`, `{tour_time}`, `{scheduled_date}`, `{scheduled_time}`
- `{event_title}`, `{event_date}`, `{event_time}`, `{start_time}`, `{end_time}`
- `{guide_name}`, `{tour_guide}`, `{tour_type}`
- `{special_requirements}`, `{preferred_language}`
- `{status}`, `{booked_at}`
- `{cancellation_link}`, `{feedback_link}`
- `{pronoun_possessive}`, `{pronoun_object}` (gender-based)
- `{key_interests}` (from CRM inquiry data)
- `{feedback_responses}`, `{submission_number}` (for admin notifications)

### Automation Features

**Scheduled Email Types:**
- 7-day reminder (configurable days)
- 1-day reminder (configurable days)
- Follow-up email (configurable days after event)
- No-show follow-up (within 24 hours of no-show marking)
- Guide first reminder (configurable days)
- Guide final reminder (configurable days)

**Automation Settings (Configurable):**
- `reminder_days_before_1` - First reminder timing (default: 7 days)
- `reminder_days_before_2` - Second reminder timing (default: 1 day)
- `followup_days_after` - Follow-up timing (default: 1 day after)
- `guide_reminder_days_before_1` - Guide first reminder (default: 3 days)
- `guide_reminder_days_before_2` - Guide final reminder (default: 1 day)

**Cron Job:**
- Runs hourly (0 * * * *) and once at startup
- Checks for eligible bookings
- Sends queued emails via sendTemplateEmail()

### Email Configuration

**Endpoints:**
- `GET /api/email-settings/:schoolId` - Get SMTP config
- `PUT /api/email-settings/:schoolId` - Update SMTP config
- `POST /api/email-settings/test` - Test SMTP connection

**SMTP Settings Stored in DB:**
- smtp_host, smtp_port, smtp_username, smtp_password
- smtp_from_email, smtp_from_name
- smtp_use_tls (boolean)
- Falls back to environment Gmail if not configured

### Email Sending Infrastructure

**getEmailTransporter():**
- Dynamically loads SMTP from database
- Fallback to environment-configured Gmail
- Supports TLS configuration

**sendTemplateEmail():**
- Core function: `sendInternalTemplateEmail(templateId, recipientEmail, templateData, attachments, ccEmail)`
- Fetches template from database
- Replaces merge fields with actual data
- Converts plain text to HTML with styling
- Intelligent button generation from URLs
- Sends with optional CC

**Email Logging:**
- `booking_email_logs` table tracks:
  - email_type, recipient, subject, sent_at
- Prevents duplicate sends via `scheduled_emails` table with status tracking

---

## 7. FEEDBACK COLLECTION & MANAGEMENT

### Two-Tier Feedback System

#### A. Tour Guide Feedback (SMART Feedback)
- Guides submit observations about student & parent
- Custom form fields configurable
- JSON response storage

**Endpoints:**
- `POST /api/tour-feedback/submit` - Guide submits feedback
- `GET /api/bookings/:id/tour-feedback` - View tour guide feedback
- `GET /api/tour-feedback-fields` - List available fields
- `POST /api/tour-feedback-fields` - Create new field
- `PUT /api/tour-feedback-fields/:id` - Update field
- `DELETE /api/tour-feedback-fields/:id` - Delete field
- `POST /api/tour-feedback-fields/reorder` - Reorder fields

**Taster Day Feedback:**
- `POST /api/feedback/taster` - Taster day specific submission
- `GET /api/bookings/:id/taster-feedback` - Retrieve taster feedback
- `GET /api/taster-feedback-fields` - Get taster field configuration

#### B. Survey/Feedback Form Questions
- Standardized feedback questions per form type
- Rating questions (1-5 scale)
- Text response questions
- Multiple choice/checkbox questions

**Endpoints:**
- `GET /api/admin/feedback-questions` - List questions
- `POST /api/admin/feedback-questions` - Create question
- `PUT /api/admin/feedback-questions/:id` - Update question
- `DELETE /api/admin/feedback-questions/:id` - Delete question

**Endpoints for Families:**
- `GET /api/feedback/booking/:token` - Get booking by feedback token
- `POST /api/feedback/submit` - Family submits feedback response

### Feedback Forms

**Endpoints:**
- `GET /api/admin/feedback-forms` - List all feedback forms
- `POST /api/admin/feedback-forms` - Create new form
- `PUT /api/admin/feedback-forms/:id` - Update form
- `DELETE /api/admin/feedback-forms/:id` - Delete form

**Form Types:**
- open_day, private_tour, taster_day
- Each can have different questions
- Forms can be assigned to specific events

**Form Fields in DB:**
- id, school_id, form_name, form_type, description, is_active
- created_at, updated_at

### Feedback Submission Features

**On Guide Feedback Submission:**
1. Records submission with timestamp
2. Increments submission_number
3. Sends notification to admissions team (async)
4. On first submission, sends personalized follow-up email to parent with feedback insights
5. Response stored as JSON: `responses` column in `tour_guide_feedback` table

**On Family Feedback Submission:**
1. Records responses in `feedback_responses` table
2. One row per question
3. Stores both: `response_value` (text) and `rating_value` (numeric)
4. Sends notification to admissions team

### Feedback Access & Display

**For Admissions Team:**
- View submitted feedback on booking detail page
- See tour guide observations
- See family survey responses
- Export feedback for reports

**For Families:**
- Access via unique feedback token in email
- Embedded form with guide observations (optional)
- Personalized follow-up content based on feedback

---

## 8. BOOKING OUTCOMES & CONVERSION TRACKING

### Outcome Tracking

**Endpoint:**
- `GET /api/bookings/:id/outcome` - Get outcome record
- `PUT /api/bookings/:id/outcome` - Create/update outcome

**Outcome Statuses:**
- `interested` - Family interested in school
- `applied` - Submitted application
- `enrolled` - Student enrolled
- `declined` - Family declined enrollment
- `(null/no_response)` - No outcome recorded yet

**Outcome Fields:**
- outcome_status (from above list)
- outcome_date (when outcome recorded)
- enrollment_year (year of enrollment if applicable)
- notes (text notes about outcome)
- created_at, updated_at timestamps

### Conversion Analytics

**Endpoint:**
- `GET /api/analytics/conversion-outcomes` - Get detailed conversion data

**Query Parameters:**
- `days` - Filter by booking age (default: 30 days, use '999999' for all)
- `type` - Filter by booking type (all, open_day, private_tour, taster_day)
- `outcome` - Filter by outcome status (all, interested, applied, enrolled, declined, no_response)
- `entryYear` - Filter by entry year

**Response includes:**
- Summary counts: interested, applied, enrolled, declined, no_response
- Detailed list of bookings with:
  - Parent & student names
  - Tour date
  - Guide assigned
  - Booking type
  - Current outcome
  - Entry year
  - Average feedback rating
  - Latest outcome status & date

**Calculations:**
- Response rate: (responses_count / total_bookings) * 100
- Conversion rate: (enrolled_count / responses_count) * 100
- Avg rating across feedback responses

---

## 9. ANALYTICS & REPORTING

### Endpoints

**Feedback Statistics:**
- `GET /api/analytics/feedback-stats` - Overall stats
  - Total bookings, response count, average rating, enrolled count
  - Response rate %, conversion rate %
  - Filterable by: days (30, 60, all), booking type

**Question Analytics:**
- `GET /api/analytics/feedback-questions` - Per-question breakdown
  - Questions grouped by form type (open_day, private_tour, taster_day)
  - For rating questions:
    - Response count, average rating, breakdown by rating (5, 4, 3, 2, 1)
  - For text questions:
    - Sample responses (up to 50), with parent name & submission date

**Conversion Analytics:**
- `GET /api/analytics/conversion-outcomes` - Outcome tracking
  - See section 8 above

### Dashboard Features (index.html)

**Tabs Available:**
1. **SMART Dashboard** - Main booking overview
2. **SMART Archive** - Historical bookings/events
3. **SMART Events & Tours** - Event management
4. **SMART Tour Guides** - Guide management
5. **SMART Form Builder** - Customize inquiry form fields
6. **SMART Survey Analytics** - Feedback reports & visualization
7. **SMART Settings** - All configuration

**Dashboard Features:**
- Upcoming events/tours list
- Recent bookings list
- Check-in status tracking
- Quick action buttons (assign guide, schedule, decline, etc.)
- Search and filter
- Responsive design for mobile check-in

---

## 10. SETTINGS & CONFIGURATION

### Setting Subtabs

**Survey Questions Tab:**
- View/add/edit feedback questions
- Set as active/inactive
- Configure per form type

**Tour Feedback Tab:**
- Configure tour guide feedback form fields
- Customize what guides report on
- Reorder fields for display

**Email Templates Tab:**
- List all templates
- Create/edit/delete templates
- Test email sending
- Configure automation triggers

**Email Configuration Tab:**
- SMTP server settings
- From address & name
- TLS settings
- Test connection
- Fallback to environment Gmail if not set

**Email Timing Tab:**
- Reminder timing (days before event)
- Follow-up timing (days after event)
- No-show follow-up timing
- Guide reminder timing
- All configurable per school

**Booking Settings Tab:**
- School name & contact info
- Booking window (how far in advance)
- Other general settings

**Prospectus Integration Tab:**
- Configuration for integrated prospectus tracking
- Links booking data with prospectus visits
- Tracks sections viewed, dwell time

**Branding Tab:**
- School logo upload (stored as base64 in DB)
- Color scheme configuration
- Custom email signatures

### Settings API

**Endpoints:**
- `GET /api/settings` - Get all settings for school
- `GET /api/booking-settings/:schoolId` - Get booking-specific settings
- `PUT /api/booking-settings/:schoolId` - Update booking settings
- `POST /api/settings/upload-logo` - Upload school logo

---

## 11. ADMINISTRATIVE FEATURES

### Booking Notes

**Endpoints:**
- `GET /api/bookings/:id/notes` - View notes on booking
- `POST /api/bookings/:id/notes` - Add new note

**Features:**
- Linked to inquiry_id in CRM
- Shows admin who created/updated note
- Timestamps for all notes
- Shared with smart CRM system

### Email History

**Endpoint:**
- `GET /api/bookings/:id/email-history` - View all emails for booking

**Includes:**
- Regular email history from CRM integration
- AI-generated email history with sentiment analysis
- Direction (sent/received)
- From/to addresses
- Subject & body text
- Timestamps

### Briefing Cards

**For Open Days:**
- `GET /api/events/:id/briefing-cards` - Get all families for event
- Grouped by tour guide
- Includes full details:
  - Family contact info
  - Student interests (from inquiry data)
  - Email history
  - Internal notes
  - Prospectus visit tracking
  - Special requirements

**For Private Tours/Taster Days:**
- `GET /api/bookings/:id/briefing-card` - Get single booking details
- Same data as open day briefing card
- Pre-print friendly format
- Guide preparation tool

### Prospectus Visit Tracking

**Integrated from tracking_events table:**
- Shows sessions/visits to prospectus
- Groups events by session_id
- Tracks:
  - Date/time of visit
  - Country (if available)
  - Sections viewed
  - Time spent per section
  - Total time on prospectus
- Displayed on briefing cards for guides

---

## 12. AUTHENTICATION & PERMISSIONS

### Admin Login

**Endpoints:**
- `POST /api/admin/login` - Login with email/password
- `GET /api/admin/check-auth` - Check session status
- `POST /api/admin/logout` - Logout

**Features:**
- Session-based auth using connect-pg-simple
- Checks: can_access_booking permission in admin_users.permissions
- 24-hour session timeout
- BCrypt password hashing

### Password Reset

**Endpoints:**
- `POST /api/admin/request-password-reset` - Request reset link
- `POST /api/admin/reset-password` - Reset with token

**Features:**
- Email with reset link
- Token-based reset (expiring)
- Password hashing with bcrypt

### Access Control

**Endpoints Protected:**
- `requireAdminAuth` - Check session.adminEmail exists
- `requireAuth` - Legacy check for session.userId

---

## 13. FORM BUILDER (INQUIRY FORMS)

### Endpoints

**Template Management:**
- `GET /api/form-template` - Get active public form
- `GET /api/form-template/manage` - Get form for admin editing
- `PUT /api/form-template/:templateId` - Update template name/description

**Form Fields:**
- `POST /api/form-field` - Create field
- `PUT /api/form-field/:fieldId` - Update field
- `DELETE /api/form-field/:fieldId` - Delete field

**Form Sections (optional organization):**
- `GET /api/form-sections/:templateId` - Get sections
- `POST /api/form-section` - Create section
- `PUT /api/form-section/:sectionId` - Update section
- `DELETE /api/form-section/:sectionId` - Delete section

**Form Submission:**
- `POST /api/form-submit` - Family submits inquiry form

### Field Types Supported

- text (short text)
- textarea (long text)
- email
- phone
- select (dropdown)
- checkbox (multiple choice)
- radio (single choice)
- date
- number

### Field Configuration

- field_label, field_name, field_type, field_options
- is_required (boolean)
- placeholder, help_text
- display_order (custom ordering)
- maps_to_inquiry_column (for auto-population of inquiry fields)
- show_for_gender (conditional display)
- section_id (for grouping)

---

## 14. PARENT SELF-SERVICE FEATURES

### Public Booking Form (book.html)
- Family fills out booking request
- Lists available dates/events
- Collects contact & student info
- Submits booking request

### Public Verify/Confirmation (book-verify.html)
- Confirmation of booking request
- Displays confirmation details
- Links to feedback forms

### Feedback Forms (Public)

**Tour Feedback Form (tour-feedback-form.html):**
- Accessible via unique feedback_token in email
- Survey questions configured by admin
- Rating scales, text responses
- Guide observations (optional display)

**Taster Feedback Form (taster-feedback-form.html):**
- Similar to tour feedback
- Customized for taster day experience

### Response/Cancellation Page (respond.html)
- Parent views declined booking with alternatives
- Can accept alternative date/time
- Or cancel booking

### Cancellation Page
- Uses cancellation_token
- Confirms cancellation
- Captures optional reason

---

## 15. DATA MODELS & RELATIONSHIPS

### Key Tables

**bookings**
- id, school_id, inquiry_id
- booking_type, status, event_id
- parent_first_name, parent_last_name, email, phone
- student_first_name, student_last_name, age_group, entry_year
- num_attendees, special_requirements, preferred_language
- scheduled_date, scheduled_time
- assigned_guide_id
- checked_in_at, checked_in_by, no_show_at
- feedback_token, cancellation_token, response_token
- created_at, updated_at, booked_at

**events**
- id, school_id, event_type, title, description
- event_date, start_time, end_time
- max_capacity, current_bookings
- assigned_feedback_form_id
- is_deleted
- created_at, updated_at

**tour_guides**
- id, school_id, name, email, phone, type
- is_active
- created_at, updated_at

**email_templates**
- id, school_id, name, booking_type, template_type
- subject, body, is_active
- enable_automation, automation_trigger, automation_days, automation_timing
- created_at, updated_at

**tour_guide_feedback**
- id, booking_id, guide_id, submission_number
- responses (JSON), submitted_at
- created_at, updated_at

**feedback_responses**
- id, booking_id, question_id
- response_value, rating_value, submitted_at

**booking_outcomes**
- id, booking_id, outcome_status, outcome_date
- enrollment_year, notes
- created_at, updated_at

**booking_email_logs**
- id, booking_id, email_type, recipient, subject, sent_at

**scheduled_emails**
- id, booking_id, email_type, scheduled_for, status
- template_id, sent_at, created_at

---

## 16. THIRD-PARTY INTEGRATIONS

### CRM Integration
- Shares admin_users table
- Links to inquiries & inquiry_notes tables
- Syncs inquiry data for bookings
- Email history shared from CRM system
- Prospectus tracking events available

### Prospectus (Embedded Module)
- Integrated via tracking_events table
- Sessions tracked with section views & dwell time
- Available on briefing cards for guide prep

---

## 17. KEY ADMIN WORKFLOWS

### Workflow 1: Create Open Day Event
1. Go to Events & Tours tab
2. Click "Create Event"
3. Fill: Title, Date, Time, Max Capacity
4. (Optional) Assign feedback form
5. Save
6. Event available for parent bookings

### Workflow 2: Manage Booking
1. Go to Dashboard tab
2. Find booking in list
3. Click to view details:
   - View family info, student interests
   - View email history
   - View internal notes (add new)
   - Assign tour guide
   - Schedule tour (sets date/time, sends emails)
   - Check in (when family arrives)
   - View feedback (if submitted)
   - Record outcome (interested/applied/enrolled/declined)

### Workflow 3: Send Reminders & Follow-ups
- **Manual:** Click "Send Email" on booking
- **Automatic:** Cron job runs hourly
  - 7-day reminder (configurable)
  - 1-day reminder (configurable)
  - Post-event follow-up (configurable)
  - No-show follow-up (within 24 hours)
  - Guide reminders (2 notifications)

### Workflow 4: Check In for Open Day
1. Go to specific event's briefing cards
2. View all confirmed bookings grouped by guide
3. Check each family in as they arrive
4. Staff member recorded automatically
5. Enables feedback & follow-up emails

### Workflow 5: View Analytics
1. Go to Survey Analytics tab
2. View feedback statistics:
   - Total responses
   - Average ratings
   - Conversion (enrolled %)
3. View per-question breakdown
4. View conversion outcomes (interested → applied → enrolled)
5. Export/share reports

### Workflow 6: Customize Email Communications
1. Go to Settings → Email Templates
2. Create/edit templates
3. Use merge fields for personalization
4. Go to Email Timing
5. Set reminder/follow-up days
6. System automatically sends on schedule

---

## 18. KEY ENDPOINTS SUMMARY BY FEATURE

### Bookings: 20+ endpoints
POST/PUT: create, update, staff-create, assign-guide, schedule, decline, checkin, reassign-guide, no-show, accept-alternative, cancel, update-outcome

### Events: 5 endpoints
CRUD operations + assign feedback form

### Tour Guides: 4 endpoints
CRUD operations

### Email Templates: 4 endpoints + test
CRUD operations + test send

### Feedback: 15+ endpoints
Forms, questions, tour feedback, taster feedback, family responses, analytics

### Settings: 5+ endpoints
Booking settings, email settings, logo upload, form templates

### Analytics: 3 endpoints
Feedback stats, per-question breakdown, conversion outcomes

### Admin: 3 endpoints
Login, logout, check-auth, password reset

---

## 19. CONFIGURATION VARIABLES

### Environment (.env)
- PORT (default 3002)
- DATABASE_URL (PostgreSQL connection)
- GMAIL_USER, GMAIL_APP_PASSWORD (email)
- EMAIL_FROM (sender address)
- SESSION_SECRET
- ADMIN_EMAIL (for notifications)
- APP_URL, BASE_URL, CRM_URL

### Database Settings (booking_settings table)
- school_id, school_name
- smtp_host, smtp_port, smtp_username, smtp_password, smtp_from_email
- reminder_days_before_1, reminder_days_before_2
- followup_days_after
- guide_reminder_days_before_1, guide_reminder_days_before_2
- logo_url, logo_data (base64)

---

## 20. SYSTEM REQUIREMENTS FOR ADMISSIONS OFFICERS

**Training Topics:**
1. Creating and managing events
2. Viewing/managing booking list
3. Assigning tour guides
4. Scheduling tours with email templates
5. Checking in families
6. Adding notes to bookings
7. Viewing/interpreting feedback
8. Tracking outcomes (interested → enrolled)
9. Using briefing cards
10. Generating analytics reports

**Daily Tasks:**
- Check incoming bookings
- Assign guides to tours
- Schedule confirmations
- Check in families
- Review feedback submissions
- Add notes about families

**Weekly Tasks:**
- Review analytics
- Track conversion rates
- Plan upcoming events
- Manage guide schedules

**Quarterly Tasks:**
- Update email templates
- Adjust reminder timing
- Analyze enrollment outcomes

---

End of Documentation
