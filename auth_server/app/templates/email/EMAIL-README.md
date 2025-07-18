# KeyN Email Template System

This directory contains the email templates for the KeyN authentication system. All email templates use a consistent design that matches your site's theming.

## Template Structure

### Base Template (`base_email.html`)
The main email template that provides:
- Consistent styling matching your site theme
- Responsive design for mobile devices
- Email client compatibility
- Inline image support using Content-ID (cid:)
- Jinja2 blocks for customization

### Email Templates

#### `verify_email.html`
Email verification template sent to new users.
- **Purpose**: Verify email address for new accounts
- **Variables**: `username`, `link`
- **Images**: Uses `cid:logo_image` and `cid:favicon_image`
- **Features**: Verification button, backup link, security info

#### `password_reset.html`
Password reset email template.
- **Purpose**: Allow users to reset forgotten passwords
- **Variables**: `username`, `link`
- **Images**: Uses `cid:logo_image` and `cid:favicon_image`
- **Features**: Reset button, security notices, expiration info

#### `welcome.html`
Welcome email sent after successful verification.
- **Purpose**: Welcome users and provide next steps
- **Variables**: `username`, `dashboard_link`, `help_link`
- **Features**: Dashboard access, getting started info

## Template Blocks

All email templates extend `base_email.html` and can override these blocks:

- `{% block title %}` - Email title (browser/client title)
- `{% block email_title %}` - Main heading in email
- `{% block email_subtitle %}` - Subtitle text below heading
- `{% block email_content %}` - Main email content
- `{% block footer_disclaimer %}` - Footer disclaimer text
- `{% block additional_css %}` - Additional CSS if needed

## Styling

The email templates use CSS variables that match your site theme:
- `--primary-color: #157347` (KeyN green)
- `--primary-hover: #0f5132` (darker green for hover)
- `--bg-color: #f8fafc` (light background)
- `--card-bg: #ffffff` (white cards)
- `--text-color: #1e1e1e` (dark text)
- `--text-secondary: #64748b` (secondary text)

## Inline Images

Images are embedded using Content-ID references:
- `src="cid:logo_image"` - Main KeyN logo in header
- `src="cid:favicon_image"` - Small favicon/key icon

The images are attached to emails in `auth_utils.py` using:
- `logo.png` for the main logo
- `favicon.png` for the favicon/key icon

These PNG files are automatically attached as inline images with proper Content-ID headers for email client compatibility.

## Creating New Email Templates

1. Create a new `.html` file in this directory
2. Extend the base template: `{% extends "email/base_email.html" %}`
3. Override the necessary blocks
4. Add your email function to `auth_utils.py`
5. Attach inline images if needed

### Example Template

```html
{% extends "email/base_email.html" %}

{% block title %}Your Custom Email - KeyN{% endblock %}
{% block email_title %}Custom Email{% endblock %}
{% block email_subtitle %}Subtitle text here{% endblock %}

{% block email_content %}
<p>Your email content goes here.</p>

<div class="button-container">
  <a href="{{ your_link }}" class="btn-primary">Action Button</a>
</div>

<div class="info-box">
  <h4>Information Box</h4>
  <ul>
    <li>List item 1</li>
    <li>List item 2</li>
  </ul>
</div>
{% endblock %}
```

## Email Client Compatibility

The templates are designed to work with:
- Gmail (web and mobile)
- Outlook (desktop and web)
- Apple Mail
- Yahoo Mail
- Thunderbird
- Mobile email clients

## Testing

Test your emails by:
1. Register a test account to trigger verification emails
2. Request password reset to test reset emails  
3. Send test emails to different email providers
4. Check appearance on mobile devices
5. Verify images load correctly
6. Test with email clients that block images

## Troubleshooting

### Images Not Showing
- Ensure PNG image files exist in `/static/logos/` directory
- Check that `logo.png` and `favicon.png` are properly sized and formatted
- Verify Content-ID headers are properly set in `auth_utils.py`
- Some email clients block images by default - users may need to enable image loading

### Styling Issues
- Email CSS is limited compared to web CSS
- Use inline styles for critical styling
- Test with multiple email clients
- Avoid advanced CSS features

### Template Errors
- Check Jinja2 syntax
- Ensure all variables are passed from the sending function
- Use proper block structure
- Test template rendering before sending

## Email Functions

The following email functions are available in `auth_utils.py`:

### `send_verification_email(user, app, mail)`
- **Purpose**: Send email verification to new users
- **Template**: `verify_email.html`
- **Attachments**: `logo.png`, `favicon.png` as inline images
- **Variables**: `username`, `link`

### `send_password_reset_email(user, app, mail)`
- **Purpose**: Send password reset link to users
- **Template**: `password_reset.html` 
- **Attachments**: `logo.png`, `favicon.png` as inline images
- **Variables**: `username`, `link`

All email functions automatically attach PNG images with proper Content-ID headers for email client compatibility.
