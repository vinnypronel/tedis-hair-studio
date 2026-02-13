# Tedi's Hair Studio

A web application for Tedi's Hair Studio. This platform provides a seamless experience for clients to book services and for the admin to manage the studio's operations.

## 🚀 Key Features

### 📅 Advanced Booking System
- **Real-Time Availability**: Clients can view and select available time slots across next 2 years.
- **Auto-Generated Slots**: Time slots are automatically generated based on business hours (Mon–Fri: 10am–8pm, Sat: 9am–5pm).
- **Phone Verification**: Optional SMS-based verification for new bookings (Twilio integration in progress).
- **Confirmation & Reminders**: Automated email and SMS confirmations, plus a 2-hour reminder before appointments (in progress).
- **Payment Method Flexibility**: Supports Zelle and Cash (Selected Upon Confirming Appointment)

### 🌟 Review Integration (Booksy Scraper)
- **Live Sync**: Uses a Puppeteer-based headless browser scraper to pull real reviews directly from the studio's Booksy profile.
- **Fallback Data**: Includes high-quality fallback reviews if the scraper is unavailable.

### 🖼️ Professional Gallery
- **Modern Layout**: A sleek, masonry-style gallery showcasing the studio's work.
- **Admin Management**: Administrators can upload new images and delete old ones directly from the dashboard.

### 🔐 Admin Suite
- **Booking Management**: View, search, and manage all client appointments.
- **Business Stats**: Quick overview of booking history and studio activity.
- **Secure Access**: Protected routes for managing the gallery and reviews.

### ✨ Modern Interface
- **Dynamic Theme Engine**: Features an iOS-inspired Dark/Light mode toggle with persistent user preferences.
- **Interactive Visuals**: Custom "Click Spark" particle effects and a stylized brand-logo pattern background.

---

## 🛠️ Technical Stack

- **Frontend**: Vanilla HTML5, CSS3, JavaScript.
- **Backend**: Node.js, Express.js.
- **Database**: Neon (Serverless PostgreSQL).

---

## 🛡️ Admin Access

The admin can access an admin only dashboard (Ctrl+Shift+a).


- **Admin User**: `****` | `**************`
- **Developer User**: `***` | `*************`


