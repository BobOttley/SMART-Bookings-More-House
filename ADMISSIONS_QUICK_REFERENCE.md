# Admissions Officer Quick Reference Guide
## More House School Booking Platform

### LOGIN
**URL:** https://smart-bookings-more-house.onrender.com
**Username:** Your email
**Password:** Your password
**Session:** 24 hours

---

## DAILY WORKFLOWS

### 1. REVIEW NEW BOOKINGS
1. Click **SMART Dashboard** tab
2. Scroll to "Recent Bookings" section
3. Filter by: Status (pending), Date (today)
4. For each booking:
   - Click to view details
   - Check student age/entry year
   - Review special requirements
   - Add internal notes if needed
   - Assign tour guide

### 2. ASSIGN TOUR GUIDE
1. Open booking details
2. Click "Assign Guide" button
3. Select from tour guide dropdown
4. Confirmation email automatically sent to guide
5. Calendar invite (.ics) attached to guide email

### 3. SCHEDULE TOUR/CONFIRM BOOKING
1. Open booking details
2. Click "Schedule Tour" button
3. Select Date & Time
4. Optionally select/confirm guide
5. Confirmation email sent to parent
6. Calendar invite sent to guide

### 4. CHECK IN FAMILY (On Day of Visit)
1. Click **SMART Dashboard** tab
2. Find booking in list OR
3. Go to **SMART Events & Tours** → Select Event → View Briefing Cards
4. Click "Check In" button next to family name
5. Timestamp recorded automatically
6. Enables feedback follow-up emails

### 5. DECLINE BOOKING WITH ALTERNATIVES
1. Open booking details
2. Click "Decline Booking" button
3. Enter reason for decline
4. Add alternative dates/times (optional)
5. Parent receives email with link to accept alternative
6. Click link to confirm new date

### 6. ACCEPT ALTERNATIVE DATE (Parent Response)
- Parent receives decline email
- Clicks "View & Accept Alternative Dates"
- Selects preferred alternative
- Automatic confirmation sent to parent
- Booking updated with new date

---

## WEEKLY WORKFLOWS

### REVIEW TOUR GUIDE FEEDBACK
1. Go to **SMART Dashboard**
2. Find booking that's been completed
3. Scroll to "Tour Guide Feedback" section
4. Review observations from guide about:
   - Student engagement
   - Family interest level
   - Academic strengths
   - Pastoral fit

### MONITOR CONVERSION PIPELINE
1. Go to **SMART Survey Analytics** tab
2. View "Conversion Outcomes" section
3. See breakdown:
   - Interested: How many families
   - Applied: How many submitted apps
   - Enrolled: How many enrolled
   - Declined: How many declined
4. Filter by entry year or booking type

### REVIEW FEEDBACK RESPONSES
1. Go to **SMART Survey Analytics** tab
2. View "Feedback Statistics":
   - Response rate % (families who gave feedback)
   - Average rating (out of 5)
   - Average satisfaction
3. View "Per-Question Breakdown"
   - See which aspects rated highest/lowest
   - Read sample text responses

---

## KEY FEATURES EXPLAINED

### EMAIL COMMUNICATIONS
- **Automatic:** System sends:
  - Reminder 7 days before visit
  - Reminder 1 day before visit
  - Follow-up 1 day after visit
  - Tour guide reminders
  
- **Manual:** Click "Send Email" button to:
  - Send custom email now
  - Use configured templates
  - Personalized with merge fields

- **Templates:** Edit under **Settings → Email Templates**
  - Merge fields like {parent_name}, {tour_date}, etc.
  - Test send before saving

### BRIEFING CARDS (Guide Preparation)
**For Open Days:**
1. Go to **SMART Events & Tours**
2. Click on the event
3. Click "View Briefing Cards"
4. See all families grouped by tour guide
5. Each card shows:
   - Family contact details
   - Student interests & academics
   - Special requirements
   - Recent email history
   - Notes from admissions

**For Private Tours:**
1. Open booking details
2. Click "Briefing Card" link
3. Print or email to guide
4. Includes family background & interests

### INTERNAL NOTES
1. Open booking details
2. Click "Add Note"
3. Type observation (shared with CRM)
4. Visible to all admissions staff
5. Searchable by date/author

### TRACK OUTCOMES
1. Open booking details
2. Scroll to "Outcome" section
3. Click "Record Outcome"
4. Select: Interested / Applied / Enrolled / Declined
5. Add enrollment year (if enrolled)
6. Add notes about conversation
7. Contributes to conversion analytics

---

## SETTINGS FOR ADMISSIONS OFFICERS

### ADJUST REMINDER TIMING
1. Go to **SMART Settings** → **Email Timing**
2. Set "Days before reminder 1" (default 7)
3. Set "Days before reminder 2" (default 1)
4. Set "Days after follow-up" (default 1)
5. Changes apply to emails sent after saving

### CUSTOMIZE EMAIL TEMPLATES
1. Go to **SMART Settings** → **Email Templates**
2. Click template to edit
3. Edit subject and body
4. Use merge fields: {parent_name}, {student_name}, {tour_date}, etc.
5. Save and test before committing

### ADD/REMOVE TOUR GUIDES
1. Go to **SMART Tour Guides** tab
2. Click "Add Guide" to create
3. Fill: Name, Email, Phone, Type
4. Check "Active" status
5. To remove: Click guide and uncheck "Active"

### CREATE NEW EVENT
1. Go to **SMART Events & Tours** tab
2. Click "Create New Event"
3. Fill:
   - Title (e.g., "December Open Day")
   - Date & Time
   - Duration
   - Max Capacity
4. Save
5. Families can now book this event

---

## COMMON ACTIONS QUICK REFERENCE

| Task | Where | How |
|------|-------|-----|
| View bookings | Dashboard | Click tab, filter by status |
| Schedule tour | Booking detail | Click "Schedule Tour" button |
| Assign guide | Booking detail | Click "Assign Guide" dropdown |
| Check in | Briefing card OR booking | Click "Check In" button |
| Add notes | Booking detail | Click "Add Note" section |
| Send email | Booking detail | Click "Send Email" button |
| Record outcome | Booking detail | Click "Outcome" section |
| View feedback | Booking detail | Scroll to "Feedback" sections |
| See analytics | Survey Analytics | View charts and stats |
| Edit templates | Settings | Email Templates tab |

---

## TROUBLESHOOTING

### Email not sending?
- Check SMTP settings under Settings → Email Configuration
- Test connection with "Send Test Email"
- Verify admin email address in settings
- Check spam folder for test emails

### Guide not receiving notification?
- Verify guide email in Tour Guides list
- Check if guide marked as "Active"
- Re-assign guide to resend notification
- Check guide spam folder

### Booking not showing feedback?
- Family must have received feedback link
- Family must have completed feedback form
- Check "checked_in_at" timestamp (must be set)
- Give family 24 hours after visit

### Can't see conversion analytics?
- Bookings must be "confirmed" status
- Must have checked in (checked_in_at set)
- Must be older than 1 day
- Outcome must be recorded by admissions

---

## KEYBOARD SHORTCUTS

| Action | Shortcut |
|--------|----------|
| New booking | Ctrl+N |
| Search bookings | Ctrl+F |
| Save | Ctrl+S |
| Logout | Alt+L |

---

## SUPPORT

**Technical Issues:**
- Contact: IT Support
- Email: support@morehousemail.org.uk

**System Training:**
- Online documentation at: /BOOKING_PLATFORM_DOCUMENTATION.md
- Schedule training session with admissions coordinator

**Questions about functionality:**
- Check documentation
- Ask admissions director
- Request feature enhancement

---

## MONTHLY REVIEW CHECKLIST

- [ ] Review last month's conversion rate
- [ ] Update event dates for next month
- [ ] Review and update tour guide list
- [ ] Update email templates if needed
- [ ] Adjust reminder timing if needed
- [ ] Generate and review feedback reports
- [ ] Identify drop-off points in pipeline (interested → applied → enrolled)
- [ ] Plan improvements based on feedback
- [ ] Update feedback questions if needed
- [ ] Review tour guide performance metrics

---

**Last Updated:** December 2024
**Version:** 1.0
