# Eldocam Back-End

This Go application provides a back-end server for handling contact forms. It receives form data, validates it, performs a Turnstile verification, and sends emails using SMTP. It also implements rate limiting to prevent abuse.

## Features

-   **Contact Form Handling:** Receives and validates contact form submissions.
-   **Turnstile Verification:** Integrates with Cloudflare Turnstile to verify submissions.
-   **Email Sending:** Sends emails to administrators and auto-replies to users.
-   **Rate Limiting:** Limits the number of requests from a single IP address to prevent abuse.

## Technologies Used

-   Go
-   [github.com/go-playground/validator/v10](https://github.com/go-playground/validator/v10): For form validation.
-   [github.com/joho/godotenv](https://github.com/joho/godotenv): For loading environment variables from a `.env` file.

## Getting Started

### Prerequisites

-   Go 1.25.1 or higher
-   A `.env` file with the following variables:

    ```
    MAIL_USER=your_email@example.com
    MAIL_PASS=your_email_password
    ADMIN_TO=admin_email@example.com
    TURNSTILE_SECRET=your_turnstile_secret
    ```

### Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/SebbeMercier/Eldocam_Back_end
    cd eldocam_back_end
    ```

2.  Install the dependencies:

    ```bash
    go mod download
    ```

### Running the Application

```bash
go run server.go
