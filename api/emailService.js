import dotenv from 'dotenv';

import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import nodemailer from 'nodemailer';
import handlebars from 'handlebars';

// Enhanced environment setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../.env');

console.log('[ENV] Loading environment from:', envPath);
dotenv.config({ path: envPath });

function getRequiredEnvVar(name) {
  const value = process.env[name];
  if (!value) {
    const error = `Missing required environment variable: ${name}`;
    console.error(`[ENV] ${error}`);
    console.error('[ENV] Available variables:', Object.keys(process.env));
    throw new Error(error);
  }
  return value;
}

const GMAIL_USER = getRequiredEnvVar('GMAIL_USER');
const GMAIL_APP_PASSWORD = getRequiredEnvVar('GMAIL_APP_PASSWORD');

console.log('[ENV] Configured with:', {
  user: GMAIL_USER,
  password: GMAIL_APP_PASSWORD ? '*** (exists)' : 'MISSING'
});

// Template handling with validation
function loadTemplate(name) {
  const templatePath = path.join(__dirname, `email-templates/${name}.hbs`);
  console.log(`[TEMPLATE] Loading template from: ${templatePath}`);

  if (!fs.existsSync(templatePath)) {
    throw new Error(`Template not found at: ${templatePath}`);
  }

  try {
    const content = fs.readFileSync(templatePath, 'utf8');
    return handlebars.compile(content);
  } catch (error) {
    console.error(`[TEMPLATE] Error loading ${name} template:`, error);
    throw new Error(`Failed to compile ${name} template`);
  }
}

const templates = {
  welcome: loadTemplate('welcome'),
  deposit: loadTemplate('deposit'),
  withdrawal: loadTemplate('withdrawal'),
  balanceUpdate: loadTemplate('balance-update'),
  depositReceipt: loadTemplate('deposit-receipt'),
  withdrawalReceipt: loadTemplate('withdrawal-receipt'),
  withdrawalCancel: loadTemplate('withdrawal-cancel')
};

// Email transporter configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  },
  tls: {
    rejectUnauthorized: process.env.NODE_ENV === 'production' // Safer TLS handling
  }
});

// Connection verification with enhanced logging
console.log('[SMTP] Verifying transporter connection...');
transporter.verify()
  .then(() => console.log('[SMTP] Connection verified successfully'))
  .catch(error => {
    console.error('[SMTP] Connection failed:', {
      code: error.code,
      command: error.command,
      response: error.response,
      stack: error.stack
    });
    throw new Error('SMTP connection verification failed');
  });

// Core email function with enhanced diagnostics
async function sendEmail(options) {
  const startTime = Date.now();
  const emailId = `${options.templateName}-${startTime}`;

  try {
    console.log(`[EMAIL] ${emailId} Starting send process to ${options.to}`);
    
    const { to, subject, templateName, templateData } = options;
    
    // Validation
    if (!to || !subject || !templateName) {
      throw new Error('Missing required email parameters');
    }

    const template = templates[templateName];
    if (!template) {
      throw new Error(`Template ${templateName} not registered`);
    }

    // Content generation
    const html = template(templateData);
    const text = html.replace(/<[^>]*>?/gm, '');
    
    const mailOptions = {
      from: `"${process.env.GMAIL_FROM_NAME || 'InvestBit'}" <${GMAIL_USER}>`,
      to,
      subject,
      text,
      html,
      headers: {
        'X-Priority': '1',
        'X-MSMail-Priority': 'High',
        'List-Unsubscribe': `<mailto:${process.env.SUPPORT_EMAIL || 'support@yourdomain.com'}>`,
        'X-Mailer': 'InvestBit/1.0'
      }
    };

    console.log(`[EMAIL] ${emailId} Prepared email:`, {
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject,
      htmlPreview: html.substring(0, 100) + '...'
    });

    // Send operation
    const result = await transporter.sendMail(mailOptions);
    console.log(`[EMAIL] ${emailId} Sent successfully in ${Date.now() - startTime}ms`, {
      messageId: result.messageId,
      response: result.response
    });
    
    return { success: true, result };

  } catch (error) {
    console.error(`[EMAIL] ${emailId} Failed after ${Date.now() - startTime}ms:`, {
      errorCode: error.code,
      command: error.command,
      response: error.response,
      stack: error.stack
    });
    
    return { 
      success: false,
      error: error.message,
      details: {
        code: error.code,
        response: error.response
      }
    };
  }
}

// Email service methods
export default {
  sendWelcomeEmail: (user) => sendEmail({
    to: user.email,
    subject: 'Welcome to InvestBit!',
    templateName: 'welcome',
    templateData: {
      name: user.name,
      email: user.email,
      signupDate: new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    }
  }),

  // ... keep other methods identical to original
};