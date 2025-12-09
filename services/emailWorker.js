/**
 * Email Worker Client
 * ===================
 * Integration with the centralised Email Worker service
 *
 * Replaces direct nodemailer calls with Worker API calls
 * for personalised, AI-generated emails.
 */

const axios = require('axios');

// Email Worker URL
const EMAIL_WORKER_URL = process.env.EMAIL_WORKER_URL || 'http://localhost:3005';

// ============================================================================
// BOOKING TRIGGERS
// ============================================================================

/**
 * Trigger open day booking confirmation email
 */
async function triggerOpenDayBooking(bookingData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'open_day_booking',
      source: 'booking_app',
      ...bookingData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering open day booking email:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Trigger private tour booking confirmation email
 */
async function triggerPrivateTourBooking(bookingData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'private_tour_booking',
      source: 'booking_app',
      ...bookingData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering private tour booking email:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Trigger taster day booking confirmation email
 */
async function triggerTasterDayBooking(bookingData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'taster_day_booking',
      source: 'booking_app',
      ...bookingData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering taster day booking email:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Trigger generic booking confirmation
 * Automatically selects the right trigger based on booking_type
 */
async function triggerBookingConfirmation(booking) {
  const bookingType = booking.booking_type || booking.type;

  switch (bookingType) {
    case 'open_day':
      return triggerOpenDayBooking(booking);
    case 'private_tour':
      return triggerPrivateTourBooking(booking);
    case 'taster_day':
      return triggerTasterDayBooking(booking);
    default:
      console.warn(`Unknown booking type: ${bookingType}, using open_day trigger`);
      return triggerOpenDayBooking(booking);
  }
}

// ============================================================================
// STAFF NOTIFICATIONS
// ============================================================================

/**
 * Trigger staff briefing email
 */
async function triggerStaffBriefing(briefingData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'staff_briefing',
      source: 'booking_app',
      ...briefingData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering staff briefing:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Trigger tour guide assignment email
 */
async function triggerGuideAssignment(assignmentData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'tour_guide_briefing',
      source: 'booking_app',
      ...assignmentData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering guide assignment:', error.message);
    return { success: false, error: error.message };
  }
}

// ============================================================================
// ENQUIRY HANDLING
// ============================================================================

/**
 * Trigger enquiry form email (with prospectus generation)
 */
async function triggerEnquiryEmail(enquiryData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'enquiry_form',
      source: 'booking_app',
      ...enquiryData
    }, { timeout: 60000 }); // Longer timeout for prospectus generation

    return response.data;
  } catch (error) {
    console.error('Error triggering enquiry email:', error.message);
    return { success: false, error: error.message };
  }
}

// ============================================================================
// REMINDER HANDLING
// ============================================================================

/**
 * Trigger event reminder email
 */
async function triggerEventReminder(reminderData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'event_reminder',
      source: 'booking_app',
      ...reminderData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error triggering event reminder:', error.message);
    return { success: false, error: error.message };
  }
}

// ============================================================================
// POLICY REQUESTS
// ============================================================================

/**
 * Send a policy document to a parent
 */
async function sendPolicy(policyData) {
  try {
    const response = await axios.post(`${EMAIL_WORKER_URL}/api/trigger`, {
      trigger_type: 'policy_request',
      source: 'booking_app',
      ...policyData
    }, { timeout: 30000 });

    return response.data;
  } catch (error) {
    console.error('Error sending policy:', error.message);
    return { success: false, error: error.message };
  }
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

/**
 * Check if the email worker is available
 */
async function checkWorkerHealth() {
  try {
    const response = await axios.get(`${EMAIL_WORKER_URL}/health`, { timeout: 5000 });
    return response.data;
  } catch (error) {
    console.error('Email worker health check failed:', error.message);
    return { status: 'error', error: error.message };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  // Booking triggers
  triggerOpenDayBooking,
  triggerPrivateTourBooking,
  triggerTasterDayBooking,
  triggerBookingConfirmation,

  // Staff notifications
  triggerStaffBriefing,
  triggerGuideAssignment,

  // Enquiries
  triggerEnquiryEmail,

  // Reminders
  triggerEventReminder,

  // Policies
  sendPolicy,

  // Utilities
  checkWorkerHealth,

  // Config
  EMAIL_WORKER_URL
};
