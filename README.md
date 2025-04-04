🌐 Social Authentication
A Django-based backend system that supports both Google OAuth login and custom API-based user authentication. It provides a secure, scalable, and RESTful interface that can be easily integrated into frontend apps, mobile apps, or microservices.

This project is ideal for developers looking to implement modern login flows using both social and traditional methods in a clean, production-ready Django setup.

🚀 Key Features
🔑 Google OAuth login integration
👥 Custom authentication via self-created APIs (register, OTP, login, password reset)
🔒 JWT-based token authentication
🛠️ Secure management of environment variables via .env
🗃️ PostgreSQL database support
🔄 Token refresh mechanism
🔧 Modular and extensible Django architecture

📦 Setup Instructions
Follow these steps to set up the project on your local machine:

1. Clone the Repository
git clone -b dev https://github.com/Satish1097/Social-Authentication.git
cd Social-Authentication

2. Create a Virtual Environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

3. Install Dependencies
pip install -r requirements.txt

4. Configure Environment Variables
Create a .env file in the root directory and add the following variables:
# Django
SECRET_KEY=your-secret-key

# Google OAuth
GOOGLE_OAUTH_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
GOOGLE_OAUTH_CALLBACK_URL=your-google-callback-url

# Email Settings
EMAIL_BACKEND=smtp
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password

# PostgreSQL DB
DB_NAME=socialauth
DB_USER=postgres
DB_PASSWORD=1234
DB_HOST=127.0.0.1
DB_PORT=5432
💡 Alternatively, you can export these variables in your terminal session.

5. Apply Migrations
python manage.py migrate

6. Run the Application
python manage.py runserver


🗄️ Database Configuration
Update your settings.py file to use environment variables:

import os

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "socialauth"),
        "USER": os.getenv("DB_USER", "postgres"),
        "PASSWORD": os.getenv("DB_PASSWORD", "1234"),
        "HOST": os.getenv("DB_HOST", "127.0.0.1"),
        "PORT": os.getenv("DB_PORT", "5432"),
    }
}

📡 API Endpoints
The following API endpoints are available for both custom and Google-based authentication:

| Method | Endpoint                                                   | Description                     |
|--------|------------------------------------------------------------|---------------------------------|
| POST   | `/new-user-register/`                                      | Register a new user             |
| POST   | `/send-otp/`                                               | Send OTP for verification       |
| POST   | `/verify-otp/`                                             | Verify OTP                      |
| POST   | `/new-login/`                                              | Login a user                    |
| POST   | `/token/refresh/`                                          | Refresh authentication token    |
| POST   | `/reset_password/`                                         | Request password reset          |
| POST   | `/password-reset-confirm/<uidb64>/<token>/`                | Confirm password reset          |
| POST   | `/google/`                                                 | Login via Google                |



📋 Technologies Used
Django & Django REST Framework
PostgreSQL
JWT Authentication
Google OAuth 2.0
dotenv for environment management


🚀 Contributing
We welcome contributions from everyone! To get started:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

📥 Postman Collection:
You can find the API endpoints in the included Postman collection file:
socialauth.postman_collection.json


## License
This project is licensed under the MIT License.
