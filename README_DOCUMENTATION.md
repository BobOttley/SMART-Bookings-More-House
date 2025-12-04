# More House School Booking Platform - Documentation Suite

This directory contains complete documentation for the Booking Platform used by More House School's Admissions department.

## DOCUMENTATION FILES

### 1. BOOKING_PLATFORM_DOCUMENTATION.md (28 KB)
**Comprehensive System Documentation**
- Complete feature list (20 major sections)
- All API endpoints documented
- Database schema and data models
- Email template system details
- Feedback collection workflows
- Analytics and reporting
- Admin workflows
- Configuration variables
- Third-party integrations

**Use this for:** Complete system understanding, feature reference, developer training

---

### 2. ADMISSIONS_QUICK_REFERENCE.md (7.5 KB)
**Day-to-Day Operations Guide**
- Daily workflow checklists
- Weekly review procedures
- Common actions quick reference table
- Troubleshooting guide
- Keyboard shortcuts
- Monthly review checklist
- Email communication features explained
- Briefing card usage
- Outcome tracking

**Use this for:** Staff training, daily operations, quick lookup

---

### 3. TECHNICAL_FEATURES_SUMMARY.md (8 KB)
**Technical Architecture Overview**
- System architecture & tech stack
- Core features at a glance
- API endpoint categories
- Database integration
- Key integrations
- Automation & scheduling
- Frontend pages overview
- Security features
- Dependencies and versions
- Error handling & logging

**Use this for:** IT staff, technical training, system administration

---

## QUICK START FOR ADMISSIONS OFFICERS

1. **First Time Login:**
   - URL: https://smart-bookings-more-house.onrender.com
   - Email: Your admin email
   - Password: Your password
   - Session lasts 24 hours

2. **First Actions:**
   - Check ADMISSIONS_QUICK_REFERENCE.md for daily workflows
   - Review "Daily Workflows" section
   - Practice assigning a guide
   - Try scheduling a test tour

3. **Common Questions:**
   - "How do I check in a family?" - See ADMISSIONS_QUICK_REFERENCE.md Section 4
   - "How do I customize email?" - See BOOKING_PLATFORM_DOCUMENTATION.md Section 6
   - "How do I track conversions?" - See BOOKING_PLATFORM_DOCUMENTATION.md Section 8

---

## SYSTEM OVERVIEW

**What it does:**
The Booking Platform manages all school visits including:
- Open Days (group family visits)
- Private Tours (individual families)
- Taster Days (student visits)

**Key capabilities:**
- Parent self-service booking
- Staff booking management
- Automated email communications
- Tour guide assignment & reminders
- Family feedback collection
- Conversion outcome tracking
- Analytics & reporting
- Event & guide management

---

## DASHBOARD TABS

1. **SMART Dashboard** - Main overview & recent bookings
2. **SMART Archive** - Historical data
3. **SMART Events & Tours** - Create & manage events
4. **SMART Tour Guides** - Manage guides & assignments
5. **SMART Form Builder** - Customize inquiry forms
6. **SMART Survey Analytics** - View feedback & reports
7. **SMART Settings** - Configure system

---

## KEY WORKFLOWS

### Manage a Booking (5 minutes)
1. Go to Dashboard
2. Click booking to open
3. Assign guide
4. Schedule tour (sends confirmation)
5. When family arrives: Check in
6. After visit: Record outcome

### Create an Event (2 minutes)
1. Go to Events & Tours
2. Click "Create Event"
3. Enter title, date, time, capacity
4. Save
5. Families can now book

### Customize an Email Template (5 minutes)
1. Go to Settings → Email Templates
2. Click template to edit
3. Edit subject/body
4. Use merge fields like {parent_name}
5. Test send
6. Save

### View Analytics (2 minutes)
1. Go to Survey Analytics tab
2. View feedback stats (response rate, avg rating)
3. View per-question breakdown
4. View conversion outcomes (interested → enrolled)

---

## DATABASE CONNECTION

**Shared with:** SMART CRM system
**Type:** PostgreSQL
**Host:** Render.com (cloud)
**Data:** Admin users, inquiries, notes, email history, tracking

**Independent Tables:** Bookings, events, guides, emails, feedback, outcomes

---

## AUTOMATED EMAILS

The system automatically sends emails on these schedules (all configurable):

| Email Type | Default Timing | Who Gets It |
|------------|-----------------|------------|
| Reminder 1 | 7 days before | Parent |
| Reminder 2 | 1 day before | Parent |
| Follow-up | 1 day after | Parent |
| Guide Reminder 1 | 3 days before | Tour Guide |
| Guide Reminder 2 | 1 day before | Tour Guide |
| No-show Follow-up | Within 24 hours | Parent |
| Feedback Request | 1 day after | Parent |
| Assignment | When assigned | Guide |

**Configure:** Settings → Email Timing

---

## FEEDBACK SYSTEM

**Two types collected:**

1. **Tour Guide Feedback** - Guide's observations about student/parent
   - Fields configurable by admin
   - Sent to admin team
   - Triggers follow-up email to parent

2. **Family Feedback** - Parents' experience survey
   - Rating questions (1-5 scale)
   - Text responses
   - Per-question analytics
   - Contributes to conversion tracking

---

## CONVERSION TRACKING

Track the path from visit → enrollment:

1. **Interested** - Family interested in school
2. **Applied** - Submitted application
3. **Enrolled** - Student enrolled
4. **Declined** - Family declined

View pipeline under: Survey Analytics → Conversion Outcomes

---

## EMAIL TEMPLATES

**Where to find:**
- Settings → Email Templates

**Edit:**
- Subject line
- Email body (plain text)
- Merge fields: {parent_name}, {student_name}, {tour_date}, {guide_name}, etc.
- Test send to your email

**Template Types:**
- Confirmation, Reminders, Follow-up, Decline, No-show
- Separate templates for each booking type

---

## BRIEFING CARDS

**Purpose:** Prepare guides before tours

**For Open Days:**
1. Go to Events & Tours
2. Click event
3. Click "View Briefing Cards"
4. Print or view by guide

**For Private Tours:**
1. Open booking
2. Click "Briefing Card"
3. Print or email to guide

**Contains:**
- Family contact details
- Student interests & background
- Special requirements
- Email history
- Internal notes

---

## SETTINGS YOU CAN CHANGE

**Email Timing:**
- Days before first reminder
- Days before final reminder
- Days after for follow-up
- Days after for no-show

**Email Templates:**
- Subject lines
- Email body text
- Merge field usage

**Tour Guides:**
- Add/remove guides
- Update contact info
- Mark active/inactive

**Events:**
- Create/edit/delete
- Set capacity
- Assign feedback form

**School Settings:**
- School name
- Contact info
- Logo upload
- SMTP configuration

---

## TROUBLESHOOTING

**Emails not sending?**
- Check SMTP settings (Settings → Email Configuration)
- Test email connection
- Check admin email address

**Guide not responding?**
- Check guide email address
- Verify guide is marked "Active"
- Re-assign to resend notification

**Feedback not showing?**
- Must check in family first
- Wait 24 hours after visit
- Family must complete feedback form

**Can't see analytics?**
- Booking must be "confirmed"
- Family must have checked in
- Must be at least 1 day old

---

## SUPPORT & HELP

**For admissions questions:**
- Contact: Admissions Director
- Reference: ADMISSIONS_QUICK_REFERENCE.md

**For technical issues:**
- Contact: IT Support
- Email: support@morehousemail.org.uk

**For detailed information:**
- Full docs: BOOKING_PLATFORM_DOCUMENTATION.md
- Technical: TECHNICAL_FEATURES_SUMMARY.md

---

## TRAINING CHECKLIST

**New admissions staff should:**
- [ ] Read ADMISSIONS_QUICK_REFERENCE.md
- [ ] Watch system demo (optional video)
- [ ] Practice creating test event
- [ ] Practice assigning guide
- [ ] Practice scheduling tour
- [ ] Try checking in
- [ ] View analytics
- [ ] Customize email template

**Time required:** 1-2 hours for competency

---

## KEY CONTACTS

**Admissions Director:** 
- Email: admissions@morehousemail.org.uk
- Phone: 020 7235 2855

**IT Support:**
- Email: support@morehousemail.org.uk
- Hours: 9 AM - 5 PM

**System Administrator:**
- Name: [Name]
- Email: [Email]
- Focus: Settings, SMTP, database

---

## SYSTEM STATISTICS

- **Booking Types:** 3 (Open Days, Private Tours, Taster Days)
- **Booking Statuses:** 6 (pending, confirmed, declined, cancelled, checked_in, no_show)
- **API Endpoints:** 70+
- **Database Tables:** 20+
- **Email Templates:** 20+ (configurable)
- **Automation Rules:** 6 (all configurable)
- **Integration Points:** 2 (SMART CRM, Prospectus)

---

## DOCUMENT VERSIONS

| Document | Version | Updated | Size |
|----------|---------|---------|------|
| BOOKING_PLATFORM_DOCUMENTATION.md | 1.0 | Dec 2024 | 28 KB |
| ADMISSIONS_QUICK_REFERENCE.md | 1.0 | Dec 2024 | 7.5 KB |
| TECHNICAL_FEATURES_SUMMARY.md | 1.0 | Dec 2024 | 8 KB |
| README_DOCUMENTATION.md | 1.0 | Dec 2024 | 5 KB |

---

## NEXT STEPS

1. **Read:** ADMISSIONS_QUICK_REFERENCE.md (15 min)
2. **Explore:** Log into system and navigate tabs
3. **Practice:** Create test event and booking
4. **Configure:** Customize email templates
5. **Reference:** Use BOOKING_PLATFORM_DOCUMENTATION.md as needed

---

**Questions?** Start with the appropriate documentation file, then contact IT Support.

