// utils/email.js - Email utility functions
const nodemailer = require('nodemailer');

// Create transporter based on environment
const createTransporter = () => {
  if (process.env.NODE_ENV === 'production') {
    // Production email configuration
    return nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  } else {
    // Development - use Ethereal Email for testing
    return nodemailer.createTransporter({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'ethereal.user@ethereal.email',
        pass: 'ethereal.pass'
      }
    });
  }
};

// Email templates
const templates = {
  'email-verification': (data) => ({
    subject: 'Verify Your Email Address',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome ${data.name}!</h2>
        <p>Thank you for registering with our Dynamic Auth System. Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${data.verificationUrl}" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Verify Email Address
          </a>
        </div>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all;">${data.verificationUrl}</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
        <hr style="margin: 30px 0;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Dynamic Auth System. Please do not reply to this email.
        </p>
      </div>
    `,
    text: `
      Welcome ${data.name}!
      
      Thank you for registering with our Dynamic Auth System. Please verify your email address by visiting this link:
      ${data.verificationUrl}
      
      If you didn't create an account, you can safely ignore this email.
    `
  }),

  'password-reset': (data) => ({
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Password Reset Request</h2>
        <p>Hello ${data.name},</p>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${data.resetUrl}" 
             style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all;">${data.resetUrl}</p>
        <p><strong>This link will expire in ${data.expiresIn}.</strong></p>
        <p>If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.</p>
        <hr style="margin: 30px 0;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Dynamic Auth System. Please do not reply to this email.
        </p>
      </div>
    `,
    text: `
      Password Reset Request
      
      Hello ${data.name},
      
      We received a request to reset your password. Visit this link to create a new password:
      ${data.resetUrl}
      
      This link will expire in ${data.expiresIn}.
      
      If you didn't request a password reset, you can safely ignore this email.
    `
  }),

  'welcome': (data) => ({
    subject: 'Welcome to Dynamic Auth System',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Welcome to Dynamic Auth System!</h2>
        <p>Hello ${data.name},</p>
        <p>Your account has been successfully created and verified. You can now access all the features of our system.</p>
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 4px; margin: 20px 0;">
          <h3>Getting Started:</h3>
          <ul>
            <li>Complete your profile information</li>
            <li>Explore the dashboard features</li>
            <li>Upload and manage your files</li>
            <li>Create and manage dynamic models</li>
          </ul>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${data.loginUrl}" 
             style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Login to Dashboard
          </a>
        </div>
        <p>If you have any questions or need help, please don't hesitate to contact our support team.</p>
        <hr style="margin: 30px 0;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Dynamic Auth System. Please do not reply to this email.
        </p>
      </div>
    `,
    text: `
      Welcome to Dynamic Auth System!
      
      Hello ${data.name},
      
      Your account has been successfully created and verified. You can now access all the features of our system.
      
      Getting Started:
      - Complete your profile information
      - Explore the dashboard features
      - Upload and manage your files
      - Create and manage dynamic models
      
      Login here: ${data.loginUrl}
      
      If you have any questions or need help, please contact our support team.
    `
  })
};

// Send email function
const sendEmail = async (options) => {
  try {
    if (!options.to || !options.subject) {
      throw new Error('Email recipient and subject are required');
    }

    const transporter = createTransporter();
    
    let emailContent = {};
    
    if (options.template && templates[options.template]) {
      // Use template
      emailContent = templates[options.template](options.data || {});
    } else {
      // Use provided content
      emailContent = {
        subject: options.subject,
        html: options.html || options.text,
        text: options.text
      };
    }

    const mailOptions = {
      from: `${process.env.FROM_NAME || 'Dynamic Auth System'} <${process.env.FROM_EMAIL || 'noreply@example.com'}>`,
      to: options.to,
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text
    };

    // Add CC and BCC if provided
    if (options.cc) mailOptions.cc = options.cc;
    if (options.bcc) mailOptions.bcc = options.bcc;

    const info = await transporter.sendMail(mailOptions);
    
    console.log('Email sent successfully:', {
      messageId: info.messageId,
      to: options.to,
      subject: emailContent.subject
    });

    // In development, log the preview URL
    if (process.env.NODE_ENV !== 'production') {
      console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
    }

    return {
      success: true,
      messageId: info.messageId,
      previewUrl: process.env.NODE_ENV !== 'production' ? nodemailer.getTestMessageUrl(info) : null
    };

  } catch (error) {
    console.error('Email sending failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Send bulk emails
const sendBulkEmail = async (recipients, options) => {
  const results = [];
  
  for (const recipient of recipients) {
    try {
      const result = await sendEmail({
        ...options,
        to: recipient.email,
        data: {
          ...options.data,
          name: recipient.name || recipient.firstName || 'User'
        }
      });
      
      results.push({
        recipient: recipient.email,
        ...result
      });
    } catch (error) {
      results.push({
        recipient: recipient.email,
        success: false,
        error: error.message
      });
    }
  }
  
  return results;
};

// Verify email configuration
const verifyEmailConfig = async () => {
  try {
    const transporter = createTransporter();
    await transporter.verify();
    console.log('Email configuration is valid');
    return true;
  } catch (error) {
    console.error('Email configuration error:', error);
    return false;
  }
};

module.exports = {
  sendEmail,
  sendBulkEmail,
  verifyEmailConfig,
  templates
};