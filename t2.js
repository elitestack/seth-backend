import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs'; // Add this line
import nodemailer from 'nodemailer';
import handlebars from 'handlebars';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '.env');

console.log('Attempting to load .env from:', envPath);
const result = dotenv.config({ path: envPath });

if (result.error) {
    console.error('Error loading .env file:', result.error);
} else {
    console.log('.env file loaded successfully:', result.parsed);
}


// At the top of emailService.js
function getRequiredEnvVar(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing required environment variable: ${name}`);
    console.error('Current environment variables:', Object.keys(process.env));
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const GMAIL_USER = getRequiredEnvVar('GMAIL_USER');
const GMAIL_APP_PASSWORD = getRequiredEnvVar('GMAIL_APP_PASSWORD');

// Then use these constants in your transporter configuration


// Add this at the top after imports
console.log('Environment variables:', {
  GMAIL_USER: GMAIL_USER,
  GMAIL_APP_PASSWORD: GMAIL_APP_PASSWORD ? '*** (exists)' : 'MISSING'
});

// Then continue with your existing code...

// Load email templates

const templates = {
  welcome: loadTemplate('welcome'),
  deposit: loadTemplate('deposit'),
  withdrawal: loadTemplate('withdrawal'),
  balanceUpdate: loadTemplate('balance-update'),
  depositReceipt: loadTemplate('deposit-receipt'),
  withdrawalReceipt: loadTemplate('withdrawal-receipt'),
  withdrawalCancel: loadTemplate('withdrawal-cancel')
};


function loadTemplate(name) {
  const templatePath = path.join(__dirname, `./email-templates/${name}.hbs`);
  const templateContent = fs.readFileSync(templatePath, 'utf8');
  return handlebars.compile(templateContent);
}

// Validate environment variables
if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
  throw new Error('Missing email configuration in environment variables');
}

// Create transporter with enhanced configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASSWORD
  },
  tls: {
    rejectUnauthorized: false // Only for development, remove in production
  }
});

// Verify connection with better error handling
transporter.verify((error, success) => {
  if (error) {
    console.error('Error verifying transporter:', error);
    console.error('Configuration used:', {
      service: 'gmail',
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD ? '*** (app password exists)' : 'MISSING'
    });
  } else {
    console.log('Server is ready to send emails');
  }
});

async function sendEmail(options) {
  try {
    const { to, subject, templateName, templateData } = options;
    
    if (!to || !subject || !templateName) {
      throw new Error('Missing required email parameters');
    }

    const template = templates[templateName];
    if (!template) {
      throw new Error(`Template ${templateName} not found`);
    }

    const html = template(templateData);
    const text = html.replace(/<[^>]*>?/gm, '');

    const mailOptions = {
      from: `"${process.env.GMAIL_FROM_NAME || 'InvestBit'}" <${process.env.GMAIL_USER}>`,
      to,
      subject,
      text,
      html
    };

    console.log(`Sending email to ${to}`);
    const result = await transporter.sendMail(mailOptions);
    return { success: true, result };
  } catch (error) {
    console.error('Email sending failed:', error);
    return { success: false, error: error.message };
  }
}

export default {
  sendWelcomeEmail: (user) => sendEmail({
    to: user.email,
    subject: 'Welcome to InvestBit!',
    templateName: 'welcome',
    templateData: {
      name: user.name,
      email: user.email,
      signupDate: new Date().toLocaleDateString()
    }
  }),

   
  sendDepositConfirmation: (user, deposit) => sendEmail({
    to: user.email,
    subject: `Deposit Confirmation - $${deposit.amount}`,
    templateName: 'deposit',
    templateData: {
      name: user.name,
      amount: deposit.amount,
      currency: deposit.currency,
      cryptoAmount: deposit.cryptoAmount,
      cryptoCurrency: deposit.cryptoCurrency,
      date: new Date().toLocaleDateString(),
      walletAddress: deposit.walletAddress
    }
  }),
  
  sendWithdrawalRequest: (user, withdrawal) => sendEmail({
    to: user.email,
    subject: `Withdrawal Request - $${withdrawal.amount}`,
    templateName: 'withdrawal',
    templateData: {
      name: user.name,
      amount: withdrawal.amount,
      currency: withdrawal.currency,
      walletAddress: withdrawal.walletAddress,
      date: new Date().toLocaleDateString()
    }
  }),

  // ... keep other methods the same

  sendBalanceUpdate: (user, action, amount, newBalance, note) =>
    sendEmail({
      to: user.email,
      subject: 'Your account balance has been updated',
      templateName: 'balanceUpdate',
      templateData: {
        name: user.name,
        action,
        amount,
        newBalance,
        note
      }
    }),

  sendDepositReceipt: (user, deposit, newBalance) =>
    sendEmail({
      to: user.email,
      subject: `Deposit Receipt - ${deposit.amount} ${deposit.currency}`,
      templateName: 'depositReceipt',
      templateData: {
        name: user.name,
        amount: deposit.amount,
        currency: deposit.currency,
        newBalance
      }
    }),

  sendWithdrawalReceipt: (user, withdrawal, newBalance) =>
    sendEmail({
      to: user.email,
      subject: `Withdrawal Receipt - ${withdrawal.amount} ${withdrawal.currency}`,
      templateName: 'withdrawalReceipt',
      templateData: {
        name: user.name,
        amount: withdrawal.amount,
        currency: withdrawal.currency,
        transactionHash: withdrawal.transactionHash,
        newBalance
      }
    }),

  sendWithdrawalCancellation: (user, withdrawal, newBalance) =>
    sendEmail({
      to: user.email,
      subject: `Withdrawal Cancelled - ${withdrawal.amount} ${withdrawal.currency}`,
      templateName: 'withdrawalCancel',
      templateData: {
        name: user.name,
        amount: withdrawal.amount,
        currency: withdrawal.currency,
        newBalance
      }
    }),

  sendCustomNotification: (user, subject, message, htmlContent) => 
    sendEmail({
      to: user.email,
      subject,
      templateName: null, // we skip handlebars if custom HTML is provided
      templateData: {},
      htmlOverride: htmlContent,
      textOverride: `Hello ${user.name},\n\n${message}\n\nThank you,\nThe Platform Team`
    })
  
};